import { logger } from './logger';

interface EnvironmentConfig {
  PORT: string;
  NODE_ENV: string;
  DATABASE_URL: string;
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
}

const requiredEnvVars: (keyof EnvironmentConfig)[] = [
  'DATABASE_URL',
  'JWT_SECRET',
];

const defaultValues: Partial<EnvironmentConfig> = {
  PORT: '3001',
  NODE_ENV: 'development',
  JWT_EXPIRES_IN: '24h',
};

export const validateEnv = (): void => {
  const missingVars: string[] = [];

  // Check for required environment variables
  requiredEnvVars.forEach((varName) => {
    if (!process.env[varName]) {
      missingVars.push(varName);
    }
  });

  // Set default values for optional variables
  Object.entries(defaultValues).forEach(([key, value]) => {
    if (!process.env[key]) {
      process.env[key] = value;
      logger.info(`Setting default value for ${key}: ${value}`);
    }
  });

  // If there are missing required variables, log them and exit
  if (missingVars.length > 0) {
    logger.error('❌ Missing required environment variables:');
    missingVars.forEach((varName) => {
      logger.error(`   - ${varName}`);
    });
    logger.error('Please check your .env file and ensure all required variables are set.');
    process.exit(1);
  }

  // Validate NODE_ENV
  const validEnvironments = ['development', 'production', 'test'];
  if (!validEnvironments.includes(process.env.NODE_ENV!)) {
    logger.warn(`Invalid NODE_ENV: ${process.env.NODE_ENV}. Setting to 'development'.`);
    process.env.NODE_ENV = 'development';
  }

  // Validate PORT
  const port = parseInt(process.env.PORT!, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    logger.warn(`Invalid PORT: ${process.env.PORT}. Setting to 3001.`);
    process.env.PORT = '3001';
  }

  logger.info('✅ Environment variables validated successfully');
};

export const getEnvConfig = (): EnvironmentConfig => {
  return {
    PORT: process.env.PORT!,
    NODE_ENV: process.env.NODE_ENV!,
    DATABASE_URL: process.env.DATABASE_URL!,
    JWT_SECRET: process.env.JWT_SECRET!,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN!,
  };
};
