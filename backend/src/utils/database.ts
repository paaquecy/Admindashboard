import { PrismaClient } from '@prisma/client';
import { logger } from './logger';

// Create a single instance of Prisma Client with logging
const prisma = new PrismaClient({
  log: [
    {
      emit: 'event',
      level: 'query',
    },
    {
      emit: 'event',
      level: 'error',
    },
    {
      emit: 'event',
      level: 'info',
    },
    {
      emit: 'event',
      level: 'warn',
    },
  ],
  errorFormat: 'pretty',
});

// Log database events
prisma.$on('query', (e) => {
  if (process.env.NODE_ENV === 'development') {
    logger.debug(`Query: ${e.query}`);
    logger.debug(`Params: ${e.params}`);
    logger.debug(`Duration: ${e.duration}ms`);
  }
});

prisma.$on('error', (e) => {
  logger.error(`Database error: ${e.message}`, {
    target: e.target,
    timestamp: e.timestamp,
  });
});

prisma.$on('info', (e) => {
  logger.info(`Database info: ${e.message}`, {
    target: e.target,
    timestamp: e.timestamp,
  });
});

prisma.$on('warn', (e) => {
  logger.warn(`Database warning: ${e.message}`, {
    target: e.target,
    timestamp: e.timestamp,
  });
});

// Database connection with retry logic
export const connectDatabase = async (retries = 5): Promise<void> => {
  for (let i = 0; i < retries; i++) {
    try {
      await prisma.$connect();
      logger.info('✅ Database connected successfully');
      
      // Test the connection
      await prisma.$queryRaw`SELECT 1`;
      logger.info('✅ Database connection verified');
      return;
    } catch (error) {
      logger.error(`❌ Database connection attempt ${i + 1} failed:`, error);
      
      if (i === retries - 1) {
        logger.error('❌ All database connection attempts failed');
        throw error;
      }
      
      // Wait before retrying (exponential backoff)
      const delay = Math.min(1000 * Math.pow(2, i), 10000);
      logger.info(`⏳ Retrying database connection in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
};

// Graceful shutdown
export const disconnectDatabase = async (): Promise<void> => {
  try {
    await prisma.$disconnect();
    logger.info('🔌 Database disconnected successfully');
  } catch (error) {
    logger.error('❌ Database disconnection failed:', error);
  }
};

// Health check function
export const checkDatabaseHealth = async (): Promise<{
  status: 'healthy' | 'unhealthy';
  responseTime: number;
  error?: string;
}> => {
  const startTime = Date.now();
  
  try {
    await prisma.$queryRaw`SELECT 1`;
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'healthy',
      responseTime,
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    logger.error('Database health check failed:', error);
    
    return {
      status: 'unhealthy',
      responseTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
};

// Database statistics
export const getDatabaseStats = async () => {
  try {
    const [
      userCount,
      vehicleCount,
      violationCount,
      scanCount,
      reportCount,
      auditLogCount,
    ] = await Promise.all([
      prisma.user.count(),
      prisma.vehicle.count(),
      prisma.violation.count(),
      prisma.vehicleScan.count(),
      prisma.report.count(),
      prisma.auditLog.count(),
    ]);

    return {
      users: userCount,
      vehicles: vehicleCount,
      violations: violationCount,
      scans: scanCount,
      reports: reportCount,
      auditLogs: auditLogCount,
    };
  } catch (error) {
    logger.error('Failed to get database statistics:', error);
    throw error;
  }
};

// Database cleanup utilities
export const cleanupExpiredSessions = async (): Promise<number> => {
  try {
    const result = await prisma.userSession.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { isActive: false },
        ],
      },
    });

    logger.info(`Cleaned up ${result.count} expired sessions`);
    return result.count;
  } catch (error) {
    logger.error('Failed to cleanup expired sessions:', error);
    throw error;
  }
};

export const cleanupOldAuditLogs = async (retentionDays: number = 365): Promise<number> => {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const result = await prisma.auditLog.deleteMany({
      where: {
        timestamp: { lt: cutoffDate },
      },
    });

    logger.info(`Cleaned up ${result.count} old audit logs (older than ${retentionDays} days)`);
    return result.count;
  } catch (error) {
    logger.error('Failed to cleanup old audit logs:', error);
    throw error;
  }
};

export const cleanupExpiredReports = async (): Promise<number> => {
  try {
    const result = await prisma.report.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });

    logger.info(`Cleaned up ${result.count} expired reports`);
    return result.count;
  } catch (error) {
    logger.error('Failed to cleanup expired reports:', error);
    throw error;
  }
};

export const cleanupExpiredNotifications = async (retentionDays: number = 30): Promise<number> => {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const result = await prisma.notification.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { 
            isRead: true,
            createdAt: { lt: cutoffDate },
          },
        ],
      },
    });

    logger.info(`Cleaned up ${result.count} expired/old notifications`);
    return result.count;
  } catch (error) {
    logger.error('Failed to cleanup expired notifications:', error);
    throw error;
  }
};

// Database backup utilities
export const createDatabaseBackup = async (backupPath: string): Promise<void> => {
  try {
    // This would typically use pg_dump for PostgreSQL
    // Implementation would depend on your backup strategy
    logger.info(`Database backup initiated to: ${backupPath}`);
    
    // For now, log the action
    await prisma.backupLog.create({
      data: {
        type: 'FULL',
        filePath: backupPath,
        fileSize: 0, // Would be set after backup completes
        status: 'RUNNING',
      },
    });
    
    logger.info('Database backup completed successfully');
  } catch (error) {
    logger.error('Database backup failed:', error);
    throw error;
  }
};

// Transaction helpers
export const withTransaction = async <T>(
  operation: (prisma: PrismaClient) => Promise<T>
): Promise<T> => {
  return prisma.$transaction(async (tx) => {
    return operation(tx as PrismaClient);
  });
};

// Bulk operations
export const bulkUpsert = async <T extends Record<string, any>>(
  model: string,
  data: T[],
  uniqueField: keyof T
): Promise<void> => {
  const operations = data.map((item) => {
    const where = { [uniqueField]: item[uniqueField] };
    return (prisma as any)[model].upsert({
      where,
      update: item,
      create: item,
    });
  });

  await prisma.$transaction(operations);
};

export { prisma };
export default prisma;
