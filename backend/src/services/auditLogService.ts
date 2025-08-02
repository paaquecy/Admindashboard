import { AuditLogData } from '../types';
import prisma from '../utils/database';
import { logger } from '../utils/logger';

class AuditLogService {
  async log(data: AuditLogData): Promise<void> {
    try {
      await prisma.auditLog.create({
        data: {
          action: data.action,
          resource: data.resource,
          resourceId: data.resourceId,
          oldValues: data.oldValues,
          newValues: data.newValues,
          description: data.description,
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
          userId: data.userId,
        }
      });
    } catch (error) {
      logger.error('Failed to create audit log:', error);
      // Don't throw error to prevent audit logging from breaking main functionality
    }
  }

  async getLogs(filters: {
    userId?: string;
    resource?: string;
    action?: string;
    dateFrom?: Date;
    dateTo?: Date;
    page?: number;
    limit?: number;
  }) {
    const {
      userId,
      resource,
      action,
      dateFrom,
      dateTo,
      page = 1,
      limit = 50
    } = filters;

    const where: any = {};

    if (userId) where.userId = userId;
    if (resource) where.resource = resource;
    if (action) where.action = action;
    
    if (dateFrom || dateTo) {
      where.timestamp = {};
      if (dateFrom) where.timestamp.gte = dateFrom;
      if (dateTo) where.timestamp.lte = dateTo;
    }

    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        include: {
          user: {
            select: {
              id: true,
              username: true,
              firstName: true,
              lastName: true
            }
          }
        },
        orderBy: { timestamp: 'desc' },
        skip: (page - 1) * limit,
        take: limit
      }),
      prisma.auditLog.count({ where })
    ]);

    return {
      logs,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    };
  }

  async getLogById(id: string) {
    return prisma.auditLog.findUnique({
      where: { id },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });
  }

  async deleteOldLogs(olderThanDays: number = 90): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const result = await prisma.auditLog.deleteMany({
      where: {
        timestamp: {
          lt: cutoffDate
        }
      }
    });

    logger.info(`Deleted ${result.count} audit logs older than ${olderThanDays} days`);
    return result.count;
  }

  async getLogStatistics(dateFrom?: Date, dateTo?: Date) {
    const where: any = {};
    
    if (dateFrom || dateTo) {
      where.timestamp = {};
      if (dateFrom) where.timestamp.gte = dateFrom;
      if (dateTo) where.timestamp.lte = dateTo;
    }

    const [
      totalLogs,
      actionStats,
      resourceStats,
      userStats
    ] = await Promise.all([
      prisma.auditLog.count({ where }),
      prisma.auditLog.groupBy({
        by: ['action'],
        where,
        _count: { action: true },
        orderBy: { _count: { action: 'desc' } }
      }),
      prisma.auditLog.groupBy({
        by: ['resource'],
        where,
        _count: { resource: true },
        orderBy: { _count: { resource: 'desc' } }
      }),
      prisma.auditLog.groupBy({
        by: ['userId'],
        where: {
          ...where,
          userId: { not: null }
        },
        _count: { userId: true },
        orderBy: { _count: { userId: 'desc' } },
        take: 10
      })
    ]);

    return {
      totalLogs,
      actionBreakdown: actionStats.map(stat => ({
        action: stat.action,
        count: stat._count.action
      })),
      resourceBreakdown: resourceStats.map(stat => ({
        resource: stat.resource,
        count: stat._count.resource
      })),
      topUsers: userStats.map(stat => ({
        userId: stat.userId,
        count: stat._count.userId
      }))
    };
  }
}

export const auditLogService = new AuditLogService();
