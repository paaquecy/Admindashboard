import Redis from 'ioredis';
import { logger } from './logger';
import { CacheManager, CacheOptions } from '../types';

// Redis client configuration
const redisConfig = {
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD || undefined,
  db: parseInt(process.env.REDIS_DB || '0'),
  retryDelayOnFailover: 100,
  enableReadyCheck: true,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
  keepAlive: 30000,
  connectTimeout: 10000,
  commandTimeout: 5000,
};

// Create Redis client
export const redisClient = new Redis(redisConfig);

// Redis event handlers
redisClient.on('connect', () => {
  logger.info('✅ Redis client connected');
});

redisClient.on('ready', () => {
  logger.info('✅ Redis client ready');
});

redisClient.on('error', (error) => {
  logger.error('❌ Redis client error:', error);
});

redisClient.on('close', () => {
  logger.warn('⚠️ Redis client connection closed');
});

redisClient.on('reconnecting', () => {
  logger.info('🔄 Redis client reconnecting...');
});

// Cache key prefixes
const CACHE_PREFIXES = {
  USER: 'user:',
  VEHICLE: 'vehicle:',
  VIOLATION: 'violation:',
  SCAN: 'scan:',
  REPORT: 'report:',
  ANALYTICS: 'analytics:',
  SESSION: 'session:',
  RATE_LIMIT: 'rate_limit:',
  HEALTH: 'health:',
  NOTIFICATION: 'notification:',
} as const;

// Default cache TTLs (in seconds)
const DEFAULT_TTLS = {
  SHORT: 300,     // 5 minutes
  MEDIUM: 1800,   // 30 minutes
  LONG: 3600,     // 1 hour
  VERY_LONG: 86400, // 24 hours
} as const;

// Cache manager implementation
class RedisCacheManager implements CacheManager {
  private generateKey(prefix: string, key: string): string {
    return `${prefix}${key}`;
  }

  async get<T>(key: string): Promise<T | null> {
    try {
      const value = await redisClient.get(key);
      if (value === null) return null;
      
      return JSON.parse(value) as T;
    } catch (error) {
      logger.error('Cache get error:', error);
      return null;
    }
  }

  async set<T>(key: string, value: T, options?: CacheOptions): Promise<void> {
    try {
      const serializedValue = JSON.stringify(value);
      const ttl = options?.ttl || DEFAULT_TTLS.MEDIUM;
      
      await redisClient.setex(key, ttl, serializedValue);
      
      // Set cache tags for invalidation
      if (options?.tags) {
        const tagPromises = options.tags.map(tag => 
          redisClient.sadd(`tag:${tag}`, key)
        );
        await Promise.all(tagPromises);
      }
    } catch (error) {
      logger.error('Cache set error:', error);
      throw error;
    }
  }

  async del(key: string): Promise<void> {
    try {
      await redisClient.del(key);
    } catch (error) {
      logger.error('Cache delete error:', error);
      throw error;
    }
  }

  async delByTags(tags: string[]): Promise<void> {
    try {
      for (const tag of tags) {
        const keys = await redisClient.smembers(`tag:${tag}`);
        if (keys.length > 0) {
          await redisClient.del(...keys);
          await redisClient.del(`tag:${tag}`);
        }
      }
    } catch (error) {
      logger.error('Cache delete by tags error:', error);
      throw error;
    }
  }

  async clear(): Promise<void> {
    try {
      await redisClient.flushdb();
      logger.info('Cache cleared successfully');
    } catch (error) {
      logger.error('Cache clear error:', error);
      throw error;
    }
  }

  // Pattern-based deletion
  async delByPattern(pattern: string): Promise<void> {
    try {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) {
        await redisClient.del(...keys);
        logger.info(`Deleted ${keys.length} keys matching pattern: ${pattern}`);
      }
    } catch (error) {
      logger.error('Cache delete by pattern error:', error);
      throw error;
    }
  }
}

export const cacheManager = new RedisCacheManager();

// Specialized cache functions

// User cache functions
export const userCache = {
  async get(userId: string) {
    return cacheManager.get(`${CACHE_PREFIXES.USER}${userId}`);
  },

  async set(userId: string, userData: any, ttl = DEFAULT_TTLS.MEDIUM) {
    return cacheManager.set(`${CACHE_PREFIXES.USER}${userId}`, userData, {
      ttl,
      tags: ['users', `user:${userId}`],
    });
  },

  async invalidate(userId: string) {
    return cacheManager.del(`${CACHE_PREFIXES.USER}${userId}`);
  },

  async invalidateAll() {
    return cacheManager.delByTags(['users']);
  },
};

// Vehicle cache functions
export const vehicleCache = {
  async get(plateNumber: string) {
    return cacheManager.get(`${CACHE_PREFIXES.VEHICLE}${plateNumber}`);
  },

  async set(plateNumber: string, vehicleData: any, ttl = DEFAULT_TTLS.LONG) {
    return cacheManager.set(`${CACHE_PREFIXES.VEHICLE}${plateNumber}`, vehicleData, {
      ttl,
      tags: ['vehicles', `vehicle:${plateNumber}`],
    });
  },

  async invalidate(plateNumber: string) {
    return cacheManager.del(`${CACHE_PREFIXES.VEHICLE}${plateNumber}`);
  },

  async invalidateAll() {
    return cacheManager.delByTags(['vehicles']);
  },
};

// Session cache functions
export const sessionCache = {
  async get(sessionId: string) {
    return cacheManager.get(`${CACHE_PREFIXES.SESSION}${sessionId}`);
  },

  async set(sessionId: string, sessionData: any, ttl?: number) {
    const sessionTtl = ttl || parseInt(process.env.SESSION_TIMEOUT_MINUTES || '30') * 60;
    return cacheManager.set(`${CACHE_PREFIXES.SESSION}${sessionId}`, sessionData, {
      ttl: sessionTtl,
      tags: ['sessions'],
    });
  },

  async invalidate(sessionId: string) {
    return cacheManager.del(`${CACHE_PREFIXES.SESSION}${sessionId}`);
  },

  async invalidateAll() {
    return cacheManager.delByTags(['sessions']);
  },
};

// Analytics cache functions
export const analyticsCache = {
  async get(cacheKey: string) {
    return cacheManager.get(`${CACHE_PREFIXES.ANALYTICS}${cacheKey}`);
  },

  async set(cacheKey: string, data: any, ttl = DEFAULT_TTLS.MEDIUM) {
    return cacheManager.set(`${CACHE_PREFIXES.ANALYTICS}${cacheKey}`, data, {
      ttl,
      tags: ['analytics'],
    });
  },

  async invalidateAll() {
    return cacheManager.delByTags(['analytics']);
  },
};

// Rate limiting functions
export const rateLimitCache = {
  async increment(key: string, windowMs: number): Promise<number> {
    const rateLimitKey = `${CACHE_PREFIXES.RATE_LIMIT}${key}`;
    const current = await redisClient.incr(rateLimitKey);
    
    if (current === 1) {
      await redisClient.expire(rateLimitKey, Math.ceil(windowMs / 1000));
    }
    
    return current;
  },

  async get(key: string): Promise<number> {
    const rateLimitKey = `${CACHE_PREFIXES.RATE_LIMIT}${key}`;
    const value = await redisClient.get(rateLimitKey);
    return parseInt(value || '0');
  },

  async reset(key: string) {
    return redisClient.del(`${CACHE_PREFIXES.RATE_LIMIT}${key}`);
  },
};

// Health check for Redis
export const checkRedisHealth = async (): Promise<{
  status: 'healthy' | 'unhealthy';
  responseTime: number;
  error?: string;
}> => {
  const startTime = Date.now();
  
  try {
    await redisClient.ping();
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'healthy',
      responseTime,
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    logger.error('Redis health check failed:', error);
    
    return {
      status: 'unhealthy',
      responseTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
};

// Cache statistics
export const getCacheStats = async () => {
  try {
    const info = await redisClient.info('memory');
    const keyspace = await redisClient.info('keyspace');
    
    // Parse memory info
    const usedMemory = info.match(/used_memory:(\d+)/)?.[1];
    const usedMemoryHuman = info.match(/used_memory_human:([^\r\n]+)/)?.[1];
    const maxMemory = info.match(/maxmemory:(\d+)/)?.[1];
    
    // Parse keyspace info
    const dbInfo = keyspace.match(/db0:keys=(\d+),expires=(\d+)/);
    const totalKeys = dbInfo ? parseInt(dbInfo[1]) : 0;
    const expiring = dbInfo ? parseInt(dbInfo[2]) : 0;
    
    return {
      usedMemory: usedMemory ? parseInt(usedMemory) : 0,
      usedMemoryHuman: usedMemoryHuman?.trim() || '0B',
      maxMemory: maxMemory ? parseInt(maxMemory) : 0,
      totalKeys,
      expiringKeys: expiring,
      hitRate: await getCacheHitRate(),
    };
  } catch (error) {
    logger.error('Failed to get cache statistics:', error);
    return null;
  }
};

// Calculate cache hit rate (simplified)
const getCacheHitRate = async (): Promise<number> => {
  try {
    const info = await redisClient.info('stats');
    const hits = info.match(/keyspace_hits:(\d+)/)?.[1];
    const misses = info.match(/keyspace_misses:(\d+)/)?.[1];
    
    if (hits && misses) {
      const totalRequests = parseInt(hits) + parseInt(misses);
      return totalRequests > 0 ? (parseInt(hits) / totalRequests) * 100 : 0;
    }
    
    return 0;
  } catch (error) {
    return 0;
  }
};

// Graceful shutdown
export const disconnectRedis = async (): Promise<void> => {
  try {
    await redisClient.quit();
    logger.info('🔌 Redis client disconnected successfully');
  } catch (error) {
    logger.error('❌ Redis disconnection failed:', error);
  }
};

export default redisClient;
