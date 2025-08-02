import { Request, Response, NextFunction } from 'express';
import { ApiError, ApiResponse } from '../types';
import { logger } from '../utils/logger';
import { Prisma } from '@prisma/client';

export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let statusCode = 500;
  let message = 'Internal server error';
  let errors: any[] = [];

  // Log the error
  logger.error('Error occurred:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
  });

  // Handle different types of errors
  if (error instanceof ApiError) {
    statusCode = error.statusCode;
    message = error.message;
  } else if (error instanceof Prisma.PrismaClientKnownRequestError) {
    // Handle Prisma errors
    switch (error.code) {
      case 'P2002':
        statusCode = 409;
        message = 'A record with this data already exists';
        const field = error.meta?.target as string[];
        if (field && field.length > 0) {
          message = `${field[0]} already exists`;
        }
        break;
      case 'P2025':
        statusCode = 404;
        message = 'Record not found';
        break;
      case 'P2003':
        statusCode = 400;
        message = 'Invalid reference to related record';
        break;
      case 'P2011':
        statusCode = 400;
        message = 'Null constraint violation';
        break;
      case 'P2012':
        statusCode = 400;
        message = 'Missing required value';
        break;
      case 'P2013':
        statusCode = 400;
        message = 'Missing required argument';
        break;
      case 'P2014':
        statusCode = 400;
        message = 'Invalid ID provided';
        break;
      case 'P2015':
        statusCode = 404;
        message = 'Related record not found';
        break;
      case 'P2016':
        statusCode = 400;
        message = 'Query interpretation error';
        break;
      case 'P2017':
        statusCode = 400;
        message = 'Records not connected';
        break;
      case 'P2018':
        statusCode = 400;
        message = 'Required connected records not found';
        break;
      case 'P2019':
        statusCode = 400;
        message = 'Input error';
        break;
      case 'P2020':
        statusCode = 400;
        message = 'Value out of range';
        break;
      case 'P2021':
        statusCode = 404;
        message = 'Table does not exist';
        break;
      case 'P2022':
        statusCode = 404;
        message = 'Column does not exist';
        break;
      default:
        statusCode = 400;
        message = 'Database operation failed';
    }
  } else if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    statusCode = 500;
    message = 'Unknown database error occurred';
  } else if (error instanceof Prisma.PrismaClientRustPanicError) {
    statusCode = 500;
    message = 'Database engine error';
  } else if (error instanceof Prisma.PrismaClientInitializationError) {
    statusCode = 500;
    message = 'Database connection error';
  } else if (error instanceof Prisma.PrismaClientValidationError) {
    statusCode = 400;
    message = 'Invalid query parameters';
  } else if (error.name === 'ValidationError') {
    // Handle express-validator errors
    statusCode = 400;
    message = 'Validation failed';
    errors = (error as any).array?.() || [];
  } else if (error.name === 'MulterError') {
    // Handle file upload errors
    statusCode = 400;
    switch ((error as any).code) {
      case 'LIMIT_FILE_SIZE':
        message = 'File size too large';
        break;
      case 'LIMIT_FILE_COUNT':
        message = 'Too many files';
        break;
      case 'LIMIT_UNEXPECTED_FILE':
        message = 'Unexpected field name';
        break;
      default:
        message = 'File upload error';
    }
  } else if (error.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  } else if (error.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
  } else if (error.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  } else if (error.name === 'SyntaxError') {
    statusCode = 400;
    message = 'Invalid JSON syntax';
  }

  // Prepare response
  const response: ApiResponse = {
    success: false,
    message,
    errors: errors.length > 0 ? errors : undefined,
  };

  // Include stack trace in development
  if (process.env.NODE_ENV === 'development') {
    (response as any).stack = error.stack;
    (response as any).originalError = error.message;
  }

  res.status(statusCode).json(response);
};

export const notFoundHandler = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const response: ApiResponse = {
    success: false,
    message: `Route ${req.originalUrl} not found`,
  };

  res.status(404).json(response);
};

// Async error handler wrapper
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Create API Error
export const createApiError = (
  message: string,
  statusCode: number = 500,
  isOperational: boolean = true
): ApiError => {
  const error = new Error(message) as ApiError;
  error.statusCode = statusCode;
  error.isOperational = isOperational;
  return error;
};
