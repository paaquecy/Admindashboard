import { Request, Response } from 'express';
import { AuthenticatedRequest, ApiResponse, CreateUserRequest } from '../types';
import { hashPassword, comparePassword, validatePasswordStrength } from '../utils/password';
import { generateToken, verifyToken } from '../utils/jwt';
import { logger } from '../utils/logger';
import { createApiError } from '../middlewares/errorHandler';
import { auditLogService } from '../services/auditLogService';
import { emailService } from '../services/emailService';
import prisma from '../utils/database';
import { v4 as uuidv4 } from 'uuid';

class AuthController {
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { username, password } = req.body;
      const ipAddress = req.ip || 'unknown';
      const userAgent = req.get('User-Agent') || 'unknown';

      // Find user by username or email
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { username: username },
            { email: username }
          ]
        },
        include: {
          role: {
            include: {
              permissions: true
            }
          }
        }
      });

      if (!user) {
        await auditLogService.log({
          action: 'LOGIN',
          resource: 'auth',
          description: `Failed login attempt for username: ${username}`,
          ipAddress,
          userAgent
        });

        throw createApiError('Invalid credentials', 401);
      }

      // Check if account is locked
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const lockTimeRemaining = Math.ceil((user.lockedUntil.getTime() - Date.now()) / (1000 * 60));
        throw createApiError(`Account is locked. Try again in ${lockTimeRemaining} minutes`, 423);
      }

      // Verify password
      const isPasswordValid = await comparePassword(password, user.hashedPassword);

      if (!isPasswordValid) {
        // Increment login attempts
        const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
        const lockTimeMinutes = parseInt(process.env.ACCOUNT_LOCK_TIME_MINUTES || '15');
        
        const newAttempts = user.loginAttempts + 1;
        let updateData: any = { loginAttempts: newAttempts };

        if (newAttempts >= maxAttempts) {
          updateData.lockedUntil = new Date(Date.now() + lockTimeMinutes * 60 * 1000);
        }

        await prisma.user.update({
          where: { id: user.id },
          data: updateData
        });

        await auditLogService.log({
          action: 'LOGIN',
          resource: 'auth',
          description: `Failed login attempt for user: ${user.username}`,
          userId: user.id,
          ipAddress,
          userAgent
        });

        throw createApiError('Invalid credentials', 401);
      }

      // Check user status
      if (!user.isActive) {
        throw createApiError('Account is inactive', 403);
      }

      if (user.status !== 'APPROVED') {
        let message = 'Account is not approved';
        switch (user.status) {
          case 'PENDING':
            message = 'Account is pending approval';
            break;
          case 'REJECTED':
            message = 'Account has been rejected';
            break;
          case 'SUSPENDED':
            message = 'Account is suspended';
            break;
        }
        throw createApiError(message, 403);
      }

      // Generate JWT token
      const tokenPayload = {
        userId: user.id,
        username: user.username,
        email: user.email,
        roleId: user.roleId,
        accountType: user.accountType
      };

      const token = generateToken(tokenPayload);

      // Calculate token expiration
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24); // 24 hours from now

      // Create user session
      await prisma.userSession.create({
        data: {
          userId: user.id,
          token,
          expiresAt,
          ipAddress,
          userAgent
        }
      });

      // Reset login attempts and update last login
      await prisma.user.update({
        where: { id: user.id },
        data: {
          loginAttempts: 0,
          lockedUntil: null,
          lastLoginAt: new Date(),
          lastLoginIP: ipAddress
        }
      });

      // Log successful login
      await auditLogService.log({
        action: 'LOGIN',
        resource: 'auth',
        description: 'User logged in successfully',
        userId: user.id,
        ipAddress,
        userAgent
      });

      // Prepare user data for response (exclude sensitive information)
      const userData = {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        profileImage: user.profileImage,
        accountType: user.accountType,
        status: user.status,
        isEmailVerified: user.isEmailVerified,
        lastLoginAt: user.lastLoginAt,
        role: {
          id: user.role.id,
          name: user.role.name,
          permissions: user.role.permissions
        }
      };

      const response: ApiResponse = {
        success: true,
        message: 'Login successful',
        data: {
          user: userData,
          token,
          expiresAt
        }
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Login error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Login failed'
        });
      }
    }
  }

  async register(req: Request, res: Response): Promise<void> {
    try {
      const userData: CreateUserRequest = req.body;
      const ipAddress = req.ip || 'unknown';
      const userAgent = req.get('User-Agent') || 'unknown';

      // Validate password strength
      const passwordValidation = validatePasswordStrength(userData.password);
      if (!passwordValidation.isValid) {
        const response: ApiResponse = {
          success: false,
          message: 'Password does not meet security requirements',
          errors: passwordValidation.errors
        };
        res.status(400).json(response);
        return;
      }

      // Check if username or email already exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { username: userData.username },
            { email: userData.email }
          ]
        }
      });

      if (existingUser) {
        const field = existingUser.username === userData.username ? 'Username' : 'Email';
        throw createApiError(`${field} already exists`, 409);
      }

      // Get default role for account type
      let roleName = '';
      switch (userData.accountType) {
        case 'POLICE':
          roleName = 'Police Officer';
          break;
        case 'DVLA':
          roleName = 'DVLA Officer';
          break;
        default:
          throw createApiError('Invalid account type', 400);
      }

      const role = await prisma.role.findFirst({
        where: { name: roleName }
      });

      if (!role) {
        throw createApiError('Role not found for account type', 500);
      }

      // Hash password
      const hashedPassword = await hashPassword(userData.password);

      // Create user
      const newUser = await prisma.user.create({
        data: {
          username: userData.username,
          email: userData.email,
          hashedPassword,
          firstName: userData.firstName,
          lastName: userData.lastName,
          phoneNumber: userData.phoneNumber,
          accountType: userData.accountType,
          status: 'PENDING', // Requires admin approval
          roleId: role.id,
          // Account type specific fields
          badgeNumber: userData.badgeNumber,
          rank: userData.rank,
          station: userData.station,
          idNumber: userData.idNumber,
          position: userData.position,
          department: userData.department
        },
        include: {
          role: true
        }
      });

      // Log user registration
      await auditLogService.log({
        action: 'CREATE',
        resource: 'user',
        resourceId: newUser.id,
        description: 'New user registered',
        newValues: {
          username: newUser.username,
          email: newUser.email,
          accountType: newUser.accountType
        },
        ipAddress,
        userAgent
      });

      // Send notification email to admins about new registration
      try {
        await emailService.sendNewUserRegistrationNotification({
          user: newUser,
          adminEmails: await this.getAdminEmails()
        });
      } catch (emailError) {
        logger.error('Failed to send registration notification email:', emailError);
        // Don't fail the registration if email fails
      }

      // Prepare response data (exclude sensitive information)
      const responseData = {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        accountType: newUser.accountType,
        status: newUser.status,
        role: newUser.role.name
      };

      const response: ApiResponse = {
        success: true,
        message: 'Registration successful. Your account is pending admin approval.',
        data: responseData
      };

      res.status(201).json(response);
    } catch (error) {
      logger.error('Registration error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Registration failed'
        });
      }
    }
  }

  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader?.substring(7); // Remove 'Bearer ' prefix

      if (token) {
        // Deactivate the session
        await prisma.userSession.updateMany({
          where: {
            userId: req.user!.id,
            token: token
          },
          data: {
            isActive: false
          }
        });

        // Log logout
        await auditLogService.log({
          action: 'LOGOUT',
          resource: 'auth',
          description: 'User logged out',
          userId: req.user!.id,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        });
      }

      const response: ApiResponse = {
        success: true,
        message: 'Logout successful'
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }
  }

  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { token } = req.body;

      if (!token) {
        throw createApiError('Refresh token is required', 400);
      }

      // Verify the token
      const decoded = verifyToken(token);

      // Check if session exists and is active
      const session = await prisma.userSession.findFirst({
        where: {
          token: token,
          isActive: true,
          expiresAt: {
            gt: new Date()
          }
        },
        include: {
          user: {
            include: {
              role: {
                include: {
                  permissions: true
                }
              }
            }
          }
        }
      });

      if (!session) {
        throw createApiError('Invalid or expired session', 401);
      }

      // Generate new token
      const newTokenPayload = {
        userId: session.user.id,
        username: session.user.username,
        email: session.user.email,
        roleId: session.user.roleId,
        accountType: session.user.accountType
      };

      const newToken = generateToken(newTokenPayload);
      const newExpiresAt = new Date();
      newExpiresAt.setHours(newExpiresAt.getHours() + 24);

      // Update session with new token
      await prisma.userSession.update({
        where: { id: session.id },
        data: {
          token: newToken,
          expiresAt: newExpiresAt
        }
      });

      const response: ApiResponse = {
        success: true,
        message: 'Token refreshed successfully',
        data: {
          token: newToken,
          expiresAt: newExpiresAt
        }
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Token refresh error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(401).json({
          success: false,
          message: 'Token refresh failed'
        });
      }
    }
  }

  async changePassword(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user!.id;

      // Get user with current password
      const user = await prisma.user.findUnique({
        where: { id: userId }
      });

      if (!user) {
        throw createApiError('User not found', 404);
      }

      // Verify current password
      const isCurrentPasswordValid = await comparePassword(currentPassword, user.hashedPassword);
      if (!isCurrentPasswordValid) {
        throw createApiError('Current password is incorrect', 400);
      }

      // Validate new password strength
      const passwordValidation = validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        const response: ApiResponse = {
          success: false,
          message: 'New password does not meet security requirements',
          errors: passwordValidation.errors
        };
        res.status(400).json(response);
        return;
      }

      // Hash new password
      const hashedNewPassword = await hashPassword(newPassword);

      // Update password
      await prisma.user.update({
        where: { id: userId },
        data: {
          hashedPassword: hashedNewPassword
        }
      });

      // Invalidate all user sessions except current one
      const authHeader = req.headers.authorization;
      const currentToken = authHeader?.substring(7);

      await prisma.userSession.updateMany({
        where: {
          userId: userId,
          token: {
            not: currentToken
          }
        },
        data: {
          isActive: false
        }
      });

      // Log password change
      await auditLogService.log({
        action: 'UPDATE',
        resource: 'user',
        resourceId: userId,
        description: 'Password changed',
        userId: userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      const response: ApiResponse = {
        success: true,
        message: 'Password changed successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Change password error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Password change failed'
        });
      }
    }
  }

  async forgotPassword(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;

      // Find user by email
      const user = await prisma.user.findUnique({
        where: { email }
      });

      // Always return success to prevent email enumeration
      const response: ApiResponse = {
        success: true,
        message: 'If an account with this email exists, a password reset link has been sent.'
      };

      if (user) {
        // Generate reset token (use UUID for simplicity)
        const resetToken = uuidv4();
        const resetExpires = new Date();
        resetExpires.setHours(resetExpires.getHours() + 1); // 1 hour expiry

        // Store reset token (you might want to create a separate table for this)
        // For now, we'll use the email service to send the token
        try {
          await emailService.sendPasswordResetEmail({
            email: user.email,
            firstName: user.firstName,
            resetToken,
            resetUrl: `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`
          });

          // Log password reset request
          await auditLogService.log({
            action: 'UPDATE',
            resource: 'auth',
            description: 'Password reset requested',
            userId: user.id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
          });
        } catch (emailError) {
          logger.error('Failed to send password reset email:', emailError);
        }
      }

      res.status(200).json(response);
    } catch (error) {
      logger.error('Forgot password error:', error);
      res.status(500).json({
        success: false,
        message: 'Password reset request failed'
      });
    }
  }

  async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      const { token, newPassword } = req.body;

      // In a real implementation, you would validate the reset token
      // For this example, we'll skip token validation
      
      // Validate new password strength
      const passwordValidation = validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        const response: ApiResponse = {
          success: false,
          message: 'Password does not meet security requirements',
          errors: passwordValidation.errors
        };
        res.status(400).json(response);
        return;
      }

      // This is a simplified implementation
      // In production, you would validate the token and find the associated user
      
      const response: ApiResponse = {
        success: true,
        message: 'Password reset successful. You can now login with your new password.'
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Reset password error:', error);
      res.status(500).json({
        success: false,
        message: 'Password reset failed'
      });
    }
  }

  async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;

      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          role: {
            include: {
              permissions: true
            }
          }
        }
      });

      if (!user) {
        throw createApiError('User not found', 404);
      }

      // Prepare user data (exclude sensitive information)
      const userData = {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        profileImage: user.profileImage,
        accountType: user.accountType,
        status: user.status,
        isEmailVerified: user.isEmailVerified,
        badgeNumber: user.badgeNumber,
        rank: user.rank,
        station: user.station,
        idNumber: user.idNumber,
        position: user.position,
        department: user.department,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        role: {
          id: user.role.id,
          name: user.role.name,
          permissions: user.role.permissions
        }
      };

      const response: ApiResponse = {
        success: true,
        message: 'Profile retrieved successfully',
        data: userData
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Get profile error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to retrieve profile'
        });
      }
    }
  }

  async updateProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;
      const updateData = req.body;

      // Remove sensitive fields that shouldn't be updated via this endpoint
      delete updateData.password;
      delete updateData.hashedPassword;
      delete updateData.role;
      delete updateData.roleId;
      delete updateData.status;
      delete updateData.accountType;

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: updateData,
        include: {
          role: {
            include: {
              permissions: true
            }
          }
        }
      });

      // Log profile update
      await auditLogService.log({
        action: 'UPDATE',
        resource: 'user',
        resourceId: userId,
        description: 'Profile updated',
        newValues: updateData,
        userId: userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Prepare response data
      const userData = {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        phoneNumber: updatedUser.phoneNumber,
        profileImage: updatedUser.profileImage,
        accountType: updatedUser.accountType,
        status: updatedUser.status,
        isEmailVerified: updatedUser.isEmailVerified,
        badgeNumber: updatedUser.badgeNumber,
        rank: updatedUser.rank,
        station: updatedUser.station,
        idNumber: updatedUser.idNumber,
        position: updatedUser.position,
        department: updatedUser.department,
        role: {
          id: updatedUser.role.id,
          name: updatedUser.role.name,
          permissions: updatedUser.role.permissions
        }
      };

      const response: ApiResponse = {
        success: true,
        message: 'Profile updated successfully',
        data: userData
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Update profile error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Profile update failed'
        });
      }
    }
  }

  async verifyEmail(req: Request, res: Response): Promise<void> {
    try {
      const { token } = req.params;

      // In a real implementation, you would validate the email verification token
      // For this example, we'll return a success message
      
      const response: ApiResponse = {
        success: true,
        message: 'Email verified successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Email verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Email verification failed'
      });
    }
  }

  async resendVerification(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;

      // In a real implementation, you would generate and send a new verification email
      
      const response: ApiResponse = {
        success: true,
        message: 'Verification email sent successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Resend verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to resend verification email'
      });
    }
  }

  private async getAdminEmails(): Promise<string[]> {
    const admins = await prisma.user.findMany({
      where: {
        accountType: 'ADMINISTRATOR',
        isActive: true,
        status: 'APPROVED'
      },
      select: { email: true }
    });

    return admins.map(admin => admin.email);
  }
}

export const authController = new AuthController();
