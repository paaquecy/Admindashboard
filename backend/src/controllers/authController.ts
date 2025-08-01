import { Request, Response } from 'express';
import { AuthenticatedRequest, ApiResponse, CreateUserRequest } from '../types';
import { hashPassword, comparePassword, validatePasswordStrength } from '../utils/password';
import { generateToken, generateRefreshToken, verifyToken } from '../utils/jwt';
import { logger } from '../utils/logger';
import { createApiError } from '../middlewares/errorHandler';
import { auditLogService } from '../services/auditLogService';
import { emailService } from '../services/emailService';
import { sessionCache, userCache } from '../utils/redis';
import prisma from '../utils/database';
import { v4 as uuidv4 } from 'uuid';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

class AuthController {
  /**
   * User login with comprehensive security checks
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { username, password, twoFactorToken } = req.body;
      const ipAddress = req.ip || 'unknown';
      const userAgent = req.get('User-Agent') || 'unknown';
      const sessionId = uuidv4();

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
          userAgent,
          riskLevel: 'MEDIUM'
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
          userAgent,
          riskLevel: newAttempts >= maxAttempts ? 'HIGH' : 'MEDIUM'
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

      // Check two-factor authentication
      if (user.twoFactorEnabled) {
        if (!twoFactorToken) {
          throw createApiError('Two-factor authentication token required', 401);
        }

        const isTokenValid = speakeasy.totp.verify({
          secret: user.twoFactorSecret!,
          encoding: 'base32',
          token: twoFactorToken,
          window: 2
        });

        if (!isTokenValid) {
          await auditLogService.log({
            action: 'LOGIN',
            resource: 'auth',
            description: 'Invalid 2FA token provided',
            userId: user.id,
            ipAddress,
            userAgent,
            riskLevel: 'HIGH'
          });

          throw createApiError('Invalid two-factor authentication token', 401);
        }
      }

      // Check concurrent sessions limit
      const maxSessions = parseInt(process.env.MAX_CONCURRENT_SESSIONS || '3');
      const activeSessions = await prisma.userSession.count({
        where: {
          userId: user.id,
          isActive: true,
          expiresAt: { gt: new Date() }
        }
      });

      if (activeSessions >= maxSessions) {
        // Deactivate oldest session
        const oldestSession = await prisma.userSession.findFirst({
          where: {
            userId: user.id,
            isActive: true
          },
          orderBy: { lastActivity: 'asc' }
        });

        if (oldestSession) {
          await prisma.userSession.update({
            where: { id: oldestSession.id },
            data: { isActive: false }
          });
        }
      }

      // Generate tokens
      const tokenPayload = {
        userId: user.id,
        username: user.username,
        email: user.email,
        roleId: user.roleId,
        accountType: user.accountType,
        sessionId
      };

      const accessToken = generateToken(tokenPayload);
      const refreshToken = generateRefreshToken({ userId: user.id, sessionId });

      // Calculate token expiration
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24); // 24 hours from now

      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(refreshExpiresAt.getDate() + 7); // 7 days from now

      // Create user session
      await prisma.userSession.create({
        data: {
          id: sessionId,
          userId: user.id,
          token: accessToken,
          refreshToken,
          expiresAt,
          refreshExpiresAt,
          ipAddress,
          userAgent,
          deviceInfo: {
            userAgent,
            ipAddress,
            timestamp: new Date().toISOString()
          }
        }
      });

      // Cache session
      await sessionCache.set(sessionId, {
        userId: user.id,
        username: user.username,
        roleId: user.roleId,
        accountType: user.accountType
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
        userAgent,
        riskLevel: 'LOW'
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
        twoFactorEnabled: user.twoFactorEnabled,
        lastLoginAt: user.lastLoginAt,
        role: {
          id: user.role.id,
          name: user.role.name,
          permissions: user.role.permissions
        },
        badgeNumber: user.badgeNumber,
        rank: user.rank,
        station: user.station,
        idNumber: user.idNumber,
        position: user.position,
        department: user.department
      };

      const response: ApiResponse = {
        success: true,
        message: 'Login successful',
        data: {
          user: userData,
          accessToken,
          refreshToken,
          expiresAt,
          sessionId
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

  /**
   * User registration with comprehensive validation
   */
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

      // Generate email verification token
      const emailVerificationToken = uuidv4();

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
        userAgent,
        riskLevel: 'LOW'
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

      // Send email verification
      try {
        await emailService.sendEmailVerification({
          email: newUser.email,
          firstName: newUser.firstName,
          verificationToken: emailVerificationToken
        });
      } catch (emailError) {
        logger.error('Failed to send email verification:', emailError);
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

  /**
   * User logout with session cleanup
   */
  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const sessionId = req.sessionId;
      const userId = req.user!.id;

      if (sessionId) {
        // Deactivate the session
        await prisma.userSession.update({
          where: { id: sessionId },
          data: { isActive: false }
        });

        // Remove from cache
        await sessionCache.invalidate(sessionId);

        // Log logout
        await auditLogService.log({
          action: 'LOGOUT',
          resource: 'auth',
          description: 'User logged out',
          userId,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          riskLevel: 'LOW'
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

  /**
   * Refresh access token
   */
  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw createApiError('Refresh token is required', 400);
      }

      // Find session with refresh token
      const session = await prisma.userSession.findFirst({
        where: {
          refreshToken: refreshToken,
          isActive: true,
          refreshExpiresAt: { gt: new Date() }
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
        throw createApiError('Invalid or expired refresh token', 401);
      }

      // Generate new access token
      const newTokenPayload = {
        userId: session.user.id,
        username: session.user.username,
        email: session.user.email,
        roleId: session.user.roleId,
        accountType: session.user.accountType,
        sessionId: session.id
      };

      const newAccessToken = generateToken(newTokenPayload);
      const newExpiresAt = new Date();
      newExpiresAt.setHours(newExpiresAt.getHours() + 24);

      // Update session with new token
      await prisma.userSession.update({
        where: { id: session.id },
        data: {
          token: newAccessToken,
          expiresAt: newExpiresAt,
          lastActivity: new Date()
        }
      });

      // Update cache
      await sessionCache.set(session.id, {
        userId: session.user.id,
        username: session.user.username,
        roleId: session.user.roleId,
        accountType: session.user.accountType
      });

      const response: ApiResponse = {
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken: newAccessToken,
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

  /**
   * Setup two-factor authentication
   */
  async setupTwoFactor(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { enabled, token } = req.body;
      const userId = req.user!.id;
      const user = req.user!;

      if (enabled) {
        if (user.twoFactorEnabled) {
          throw createApiError('Two-factor authentication is already enabled', 400);
        }

        // Generate secret
        const secret = speakeasy.generateSecret({
          name: `${process.env.TOTP_SERVICE_NAME} (${user.email})`,
          issuer: process.env.TOTP_ISSUER || 'PlateRecognition'
        });

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);

        // Verify token before enabling
        if (token) {
          const isTokenValid = speakeasy.totp.verify({
            secret: secret.base32,
            encoding: 'base32',
            token: token,
            window: 2
          });

          if (!isTokenValid) {
            throw createApiError('Invalid verification token', 400);
          }

          // Enable 2FA
          await prisma.user.update({
            where: { id: userId },
            data: {
              twoFactorEnabled: true,
              twoFactorSecret: secret.base32
            }
          });

          // Log 2FA setup
          await auditLogService.log({
            action: 'UPDATE',
            resource: 'user',
            resourceId: userId,
            description: 'Two-factor authentication enabled',
            userId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            riskLevel: 'LOW'
          });

          const response: ApiResponse = {
            success: true,
            message: 'Two-factor authentication enabled successfully'
          };

          res.status(200).json(response);
        } else {
          // Return secret and QR code for setup
          const response: ApiResponse = {
            success: true,
            message: 'Two-factor authentication setup initiated',
            data: {
              secret: secret.base32,
              qrCode: qrCodeUrl,
              manualEntryKey: secret.base32
            }
          };

          res.status(200).json(response);
        }
      } else {
        // Disable 2FA
        if (!user.twoFactorEnabled) {
          throw createApiError('Two-factor authentication is not enabled', 400);
        }

        if (!token) {
          throw createApiError('Current 2FA token required to disable', 400);
        }

        const isTokenValid = speakeasy.totp.verify({
          secret: user.twoFactorSecret!,
          encoding: 'base32',
          token: token,
          window: 2
        });

        if (!isTokenValid) {
          throw createApiError('Invalid verification token', 400);
        }

        await prisma.user.update({
          where: { id: userId },
          data: {
            twoFactorEnabled: false,
            twoFactorSecret: null
          }
        });

        // Log 2FA disable
        await auditLogService.log({
          action: 'UPDATE',
          resource: 'user',
          resourceId: userId,
          description: 'Two-factor authentication disabled',
          userId,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          riskLevel: 'MEDIUM'
        });

        const response: ApiResponse = {
          success: true,
          message: 'Two-factor authentication disabled successfully'
        };

        res.status(200).json(response);
      }
    } catch (error) {
      logger.error('Two-factor setup error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Two-factor authentication setup failed'
        });
      }
    }
  }

  /**
   * Get current user profile
   */
  async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user!.id;

      // Try to get from cache first
      let userData = await userCache.get(userId);

      if (!userData) {
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
        userData = {
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
          twoFactorEnabled: user.twoFactorEnabled,
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

        // Cache user data
        await userCache.set(userId, userData);
      }

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
