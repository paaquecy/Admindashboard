import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest, ApiError } from '../types';
import { verifyToken } from '../utils/jwt';
import { logger } from '../utils/logger';
import prisma from '../utils/database';

export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      const error = new Error('Access token is required') as ApiError;
      error.statusCode = 401;
      throw error;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify the token
    const decoded = verifyToken(token);

    // Get user from database with role information
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: {
        role: {
          include: {
            permissions: true
          }
        }
      }
    });

    if (!user) {
      const error = new Error('User not found') as ApiError;
      error.statusCode = 401;
      throw error;
    }

    // Check if user is active
    if (!user.isActive) {
      const error = new Error('User account is inactive') as ApiError;
      error.statusCode = 401;
      throw error;
    }

    // Check if user is approved
    if (user.status !== 'APPROVED') {
      const error = new Error('User account is not approved') as ApiError;
      error.statusCode = 403;
      throw error;
    }

    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const error = new Error('Account is temporarily locked') as ApiError;
      error.statusCode = 403;
      throw error;
    }

    // Check for valid session
    const session = await prisma.userSession.findFirst({
      where: {
        userId: user.id,
        token: token,
        isActive: true,
        expiresAt: {
          gt: new Date()
        }
      }
    });

    if (!session) {
      const error = new Error('Invalid or expired session') as ApiError;
      error.statusCode = 401;
      throw error;
    }

    // Attach user to request
    req.user = user;

    // Update last activity
    await prisma.userSession.update({
      where: { id: session.id },
      data: { 
        updatedAt: new Date(),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      }
    });

    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    
    if (error instanceof Error && 'statusCode' in error) {
      res.status((error as ApiError).statusCode).json({
        success: false,
        message: error.message,
        data: null
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Authentication failed',
        data: null
      });
    }
  }
};

export const authorize = (permissions: string[]) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!req.user) {
        const error = new Error('User not authenticated') as ApiError;
        error.statusCode = 401;
        throw error;
      }

      const userPermissions = req.user.role.permissions.map(
        p => `${p.resource}:${p.action}`
      );

      // Check if user has any of the required permissions
      const hasPermission = permissions.some(permission => 
        userPermissions.includes(permission)
      );

      // Super admin bypass (if role is 'administrator')
      const isSuperAdmin = req.user.role.name.toLowerCase() === 'administrator';

      if (!hasPermission && !isSuperAdmin) {
        const error = new Error('Insufficient permissions') as ApiError;
        error.statusCode = 403;
        throw error;
      }

      next();
    } catch (error) {
      logger.error('Authorization error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        res.status((error as ApiError).statusCode).json({
          success: false,
          message: error.message,
          data: null
        });
      } else {
        res.status(403).json({
          success: false,
          message: 'Authorization failed',
          data: null
        });
      }
    }
  };
};

export const requireAccountType = (accountTypes: string[]) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!req.user) {
        const error = new Error('User not authenticated') as ApiError;
        error.statusCode = 401;
        throw error;
      }

      if (!accountTypes.includes(req.user.accountType)) {
        const error = new Error('Account type not authorized for this action') as ApiError;
        error.statusCode = 403;
        throw error;
      }

      next();
    } catch (error) {
      logger.error('Account type authorization error:', error);
      
      if (error instanceof Error && 'statusCode' in error) {
        res.status((error as ApiError).statusCode).json({
          success: false,
          message: error.message,
          data: null
        });
      } else {
        res.status(403).json({
          success: false,
          message: 'Account type authorization failed',
          data: null
        });
      }
    }
  };
};

export const optionalAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // No token provided, continue without authentication
      next();
      return;
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = verifyToken(token);
      
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        include: {
          role: {
            include: {
              permissions: true
            }
          }
        }
      });

      if (user && user.isActive && user.status === 'APPROVED') {
        req.user = user;
      }
    } catch (error) {
      // Invalid token, but continue without authentication
      logger.warn('Optional authentication failed:', error);
    }

    next();
  } catch (error) {
    logger.error('Optional authentication error:', error);
    next(); // Continue even if optional auth fails
  }
};
