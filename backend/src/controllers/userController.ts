import { Response } from 'express';
import { AuthenticatedRequest, ApiResponse, CreateUserRequest, UpdateUserRequest } from '../types';
import { hashPassword, generateRandomPassword } from '../utils/password';
import { logger } from '../utils/logger';
import { createApiError } from '../middlewares/errorHandler';
import { auditLogService } from '../services/auditLogService';
import { emailService } from '../services/emailService';
import prisma from '../utils/database';

class UserController {
  async getUsers(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const {
        page = 1,
        limit = 10,
        search,
        status,
        accountType,
        roleId,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      const pageNum = parseInt(page as string);
      const limitNum = parseInt(limit as string);
      const skip = (pageNum - 1) * limitNum;

      // Build where clause
      const where: any = {};

      if (search) {
        where.OR = [
          { firstName: { contains: search as string, mode: 'insensitive' } },
          { lastName: { contains: search as string, mode: 'insensitive' } },
          { username: { contains: search as string, mode: 'insensitive' } },
          { email: { contains: search as string, mode: 'insensitive' } }
        ];
      }

      if (status) where.status = status;
      if (accountType) where.accountType = accountType;
      if (roleId) where.roleId = roleId;

      const [users, total] = await Promise.all([
        prisma.user.findMany({
          where,
          include: {
            role: {
              select: {
                id: true,
                name: true
              }
            }
          },
          orderBy: { [sortBy as string]: sortOrder as 'asc' | 'desc' },
          skip,
          take: limitNum
        }),
        prisma.user.count({ where })
      ]);

      // Remove sensitive data
      const sanitizedUsers = users.map(user => ({
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        profileImage: user.profileImage,
        accountType: user.accountType,
        status: user.status,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        role: user.role,
        badgeNumber: user.badgeNumber,
        rank: user.rank,
        station: user.station,
        idNumber: user.idNumber,
        position: user.position,
        department: user.department
      }));

      const response: ApiResponse = {
        success: true,
        message: 'Users retrieved successfully',
        data: sanitizedUsers,
        meta: {
          total,
          page: pageNum,
          limit: limitNum,
          totalPages: Math.ceil(total / limitNum)
        }
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Get users error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve users'
      });
    }
  }

  async getPendingUsers(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const {
        page = 1,
        limit = 10,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      const pageNum = parseInt(page as string);
      const limitNum = parseInt(limit as string);
      const skip = (pageNum - 1) * limitNum;

      const [users, total] = await Promise.all([
        prisma.user.findMany({
          where: { status: 'PENDING' },
          include: {
            role: {
              select: {
                id: true,
                name: true
              }
            }
          },
          orderBy: { [sortBy as string]: sortOrder as 'asc' | 'desc' },
          skip,
          take: limitNum
        }),
        prisma.user.count({ where: { status: 'PENDING' } })
      ]);

      const sanitizedUsers = users.map(user => ({
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        accountType: user.accountType,
        status: user.status,
        createdAt: user.createdAt,
        role: user.role,
        badgeNumber: user.badgeNumber,
        rank: user.rank,
        station: user.station,
        idNumber: user.idNumber,
        position: user.position,
        department: user.department
      }));

      const response: ApiResponse = {
        success: true,
        message: 'Pending users retrieved successfully',
        data: sanitizedUsers,
        meta: {
          total,
          page: pageNum,
          limit: limitNum,
          totalPages: Math.ceil(total / limitNum)
        }
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Get pending users error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve pending users'
      });
    }
  }

  async getUserById(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      const user = await prisma.user.findUnique({
        where: { id },
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

      const sanitizedUser = {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phoneNumber: user.phoneNumber,
        profileImage: user.profileImage,
        accountType: user.accountType,
        status: user.status,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        role: user.role,
        badgeNumber: user.badgeNumber,
        rank: user.rank,
        station: user.station,
        idNumber: user.idNumber,
        position: user.position,
        department: user.department
      };

      const response: ApiResponse = {
        success: true,
        message: 'User retrieved successfully',
        data: sanitizedUser
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Get user by ID error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to retrieve user'
        });
      }
    }
  }

  async createUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userData: CreateUserRequest = req.body;

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

      // Verify role exists
      const role = await prisma.role.findUnique({
        where: { id: userData.roleId }
      });

      if (!role) {
        throw createApiError('Role not found', 404);
      }

      // Generate temporary password
      const tempPassword = generateRandomPassword();
      const hashedPassword = await hashPassword(tempPassword);

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
          status: 'APPROVED', // Admin-created users are automatically approved
          roleId: userData.roleId,
          createdBy: req.user!.id,
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

      // Log user creation
      await auditLogService.log({
        action: 'CREATE',
        resource: 'user',
        resourceId: newUser.id,
        description: 'User created by admin',
        newValues: {
          username: newUser.username,
          email: newUser.email,
          accountType: newUser.accountType
        },
        userId: req.user!.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Send welcome email with temporary password
      try {
        await emailService.sendEmail({
          to: newUser.email,
          subject: 'Welcome to Plate Recognition System',
          template: 'welcomeUser',
          data: {
            firstName: newUser.firstName,
            username: newUser.username,
            tempPassword: tempPassword,
            loginUrl: `${process.env.FRONTEND_URL}/login`
          }
        });
      } catch (emailError) {
        logger.error('Failed to send welcome email:', emailError);
      }

      const sanitizedUser = {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        accountType: newUser.accountType,
        status: newUser.status,
        role: newUser.role,
        tempPassword: tempPassword // Include in response for admin
      };

      const response: ApiResponse = {
        success: true,
        message: 'User created successfully',
        data: sanitizedUser
      };

      res.status(201).json(response);
    } catch (error) {
      logger.error('Create user error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to create user'
        });
      }
    }
  }

  async updateUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const updateData: UpdateUserRequest = req.body;

      // Check if user exists
      const existingUser = await prisma.user.findUnique({
        where: { id }
      });

      if (!existingUser) {
        throw createApiError('User not found', 404);
      }

      // Check for email uniqueness if email is being updated
      if (updateData.email && updateData.email !== existingUser.email) {
        const emailExists = await prisma.user.findFirst({
          where: {
            email: updateData.email,
            id: { not: id }
          }
        });

        if (emailExists) {
          throw createApiError('Email already exists', 409);
        }
      }

      // Update user
      const updatedUser = await prisma.user.update({
        where: { id },
        data: updateData,
        include: {
          role: true
        }
      });

      // Log user update
      await auditLogService.log({
        action: 'UPDATE',
        resource: 'user',
        resourceId: id,
        description: 'User updated',
        oldValues: existingUser,
        newValues: updateData,
        userId: req.user!.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      const sanitizedUser = {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        phoneNumber: updatedUser.phoneNumber,
        accountType: updatedUser.accountType,
        status: updatedUser.status,
        isActive: updatedUser.isActive,
        role: updatedUser.role,
        updatedAt: updatedUser.updatedAt
      };

      const response: ApiResponse = {
        success: true,
        message: 'User updated successfully',
        data: sanitizedUser
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Update user error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to update user'
        });
      }
    }
  }

  async deleteUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      // Check if user exists
      const user = await prisma.user.findUnique({
        where: { id }
      });

      if (!user) {
        throw createApiError('User not found', 404);
      }

      // Prevent self-deletion
      if (id === req.user!.id) {
        throw createApiError('Cannot delete your own account', 400);
      }

      // Instead of hard delete, we'll deactivate the user
      const updatedUser = await prisma.user.update({
        where: { id },
        data: {
          isActive: false,
          status: 'INACTIVE'
        }
      });

      // Log user deletion
      await auditLogService.log({
        action: 'DELETE',
        resource: 'user',
        resourceId: id,
        description: 'User deactivated',
        oldValues: user,
        userId: req.user!.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      const response: ApiResponse = {
        success: true,
        message: 'User deactivated successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Delete user error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to delete user'
        });
      }
    }
  }

  async approveUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { action, reason } = req.body;

      const user = await prisma.user.findUnique({
        where: { id }
      });

      if (!user) {
        throw createApiError('User not found', 404);
      }

      if (user.status !== 'PENDING') {
        throw createApiError('User is not pending approval', 400);
      }

      const updateData: any = {
        status: action === 'approve' ? 'APPROVED' : 'REJECTED'
      };

      if (action === 'approve') {
        updateData.approvedAt = new Date();
        updateData.approvedBy = req.user!.id;
      } else {
        updateData.rejectedAt = new Date();
        updateData.rejectedBy = req.user!.id;
        updateData.rejectionReason = reason;
      }

      const updatedUser = await prisma.user.update({
        where: { id },
        data: updateData
      });

      // Log approval/rejection
      await auditLogService.log({
        action: action === 'approve' ? 'APPROVE' : 'REJECT',
        resource: 'user',
        resourceId: id,
        description: `User ${action}d`,
        newValues: { status: updateData.status, reason },
        userId: req.user!.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Send notification email
      try {
        await emailService.sendUserApprovalNotification({
          user: updatedUser,
          approved: action === 'approve',
          reason
        });
      } catch (emailError) {
        logger.error('Failed to send approval notification email:', emailError);
      }

      const response: ApiResponse = {
        success: true,
        message: `User ${action}d successfully`
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Approve user error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to process user approval'
        });
      }
    }
  }

  async updateUserStatus(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body;

      const user = await prisma.user.findUnique({
        where: { id }
      });

      if (!user) {
        throw createApiError('User not found', 404);
      }

      const updatedUser = await prisma.user.update({
        where: { id },
        data: { status }
      });

      // Log status update
      await auditLogService.log({
        action: 'UPDATE',
        resource: 'user',
        resourceId: id,
        description: `User status changed to ${status}`,
        oldValues: { status: user.status },
        newValues: { status },
        userId: req.user!.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      const response: ApiResponse = {
        success: true,
        message: 'User status updated successfully'
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Update user status error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to update user status'
        });
      }
    }
  }

  async resetUserPassword(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      const user = await prisma.user.findUnique({
        where: { id }
      });

      if (!user) {
        throw createApiError('User not found', 404);
      }

      // Generate new temporary password
      const tempPassword = generateRandomPassword();
      const hashedPassword = await hashPassword(tempPassword);

      await prisma.user.update({
        where: { id },
        data: { hashedPassword }
      });

      // Invalidate all user sessions
      await prisma.userSession.updateMany({
        where: { userId: id },
        data: { isActive: false }
      });

      // Log password reset
      await auditLogService.log({
        action: 'UPDATE',
        resource: 'user',
        resourceId: id,
        description: 'Password reset by admin',
        userId: req.user!.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Send new password email
      try {
        await emailService.sendEmail({
          to: user.email,
          subject: 'Password Reset',
          template: 'passwordResetByAdmin',
          data: {
            firstName: user.firstName,
            tempPassword: tempPassword,
            loginUrl: `${process.env.FRONTEND_URL}/login`
          }
        });
      } catch (emailError) {
        logger.error('Failed to send password reset email:', emailError);
      }

      const response: ApiResponse = {
        success: true,
        message: 'Password reset successfully',
        data: { tempPassword } // Include in response for admin
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Reset user password error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        const apiError = error as any;
        res.status(apiError.statusCode).json({
          success: false,
          message: apiError.message
        });
      } else {
        res.status(500).json({
          success: false,
          message: 'Failed to reset user password'
        });
      }
    }
  }

  async getUserActivity(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { page = 1, limit = 20 } = req.query;

      const result = await auditLogService.getLogs({
        userId: id,
        page: parseInt(page as string),
        limit: parseInt(limit as string)
      });

      const response: ApiResponse = {
        success: true,
        message: 'User activity retrieved successfully',
        data: result.logs,
        meta: result.pagination
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Get user activity error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user activity'
      });
    }
  }

  async getUserStats(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const [
        totalUsers,
        pendingApprovals,
        activeUsers,
        suspendedUsers,
        accountTypeStats,
        recentRegistrations
      ] = await Promise.all([
        prisma.user.count(),
        prisma.user.count({ where: { status: 'PENDING' } }),
        prisma.user.count({ where: { isActive: true, status: 'APPROVED' } }),
        prisma.user.count({ where: { status: 'SUSPENDED' } }),
        prisma.user.groupBy({
          by: ['accountType'],
          _count: { accountType: true }
        }),
        prisma.user.count({
          where: {
            createdAt: {
              gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
            }
          }
        })
      ]);

      const stats = {
        totalUsers,
        pendingApprovals,
        activeUsers,
        suspendedUsers,
        recentRegistrations,
        accountTypeBreakdown: accountTypeStats.map(stat => ({
          accountType: stat.accountType,
          count: stat._count.accountType
        }))
      };

      const response: ApiResponse = {
        success: true,
        message: 'User statistics retrieved successfully',
        data: stats
      };

      res.status(200).json(response);
    } catch (error) {
      logger.error('Get user stats error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user statistics'
      });
    }
  }
}

export const userController = new UserController();
