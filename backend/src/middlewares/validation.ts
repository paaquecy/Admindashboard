import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import { ApiResponse } from '../types';

export const validateRequest = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const response: ApiResponse = {
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(error => ({
        field: error.type === 'field' ? (error as any).path : error.type,
        message: error.msg,
        value: error.type === 'field' ? (error as any).value : undefined,
      })),
    };
    
    res.status(400).json(response);
    return;
  }
  
  next();
};

export const sanitizeRequestBody = (allowedFields: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.body && typeof req.body === 'object') {
      const sanitizedBody: any = {};
      
      allowedFields.forEach(field => {
        if (req.body.hasOwnProperty(field)) {
          sanitizedBody[field] = req.body[field];
        }
      });
      
      req.body = sanitizedBody;
    }
    
    next();
  };
};

export const validatePagination = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const { page, limit, sortBy, sortOrder } = req.query;
  
  // Validate page
  if (page && (isNaN(Number(page)) || Number(page) < 1)) {
    const response: ApiResponse = {
      success: false,
      message: 'Page must be a positive integer',
    };
    res.status(400).json(response);
    return;
  }
  
  // Validate limit
  if (limit && (isNaN(Number(limit)) || Number(limit) < 1 || Number(limit) > 100)) {
    const response: ApiResponse = {
      success: false,
      message: 'Limit must be a positive integer between 1 and 100',
    };
    res.status(400).json(response);
    return;
  }
  
  // Validate sort order
  if (sortOrder && !['asc', 'desc'].includes(sortOrder as string)) {
    const response: ApiResponse = {
      success: false,
      message: 'Sort order must be either "asc" or "desc"',
    };
    res.status(400).json(response);
    return;
  }
  
  next();
};

export const validateIdParam = (paramName: string = 'id') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const id = req.params[paramName];
    
    if (!id || typeof id !== 'string' || id.trim().length === 0) {
      const response: ApiResponse = {
        success: false,
        message: `Invalid ${paramName} parameter`,
      };
      res.status(400).json(response);
      return;
    }
    
    next();
  };
};

export const validateDateRange = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const { dateFrom, dateTo } = req.query;
  
  if (dateFrom && isNaN(Date.parse(dateFrom as string))) {
    const response: ApiResponse = {
      success: false,
      message: 'Invalid dateFrom format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss)',
    };
    res.status(400).json(response);
    return;
  }
  
  if (dateTo && isNaN(Date.parse(dateTo as string))) {
    const response: ApiResponse = {
      success: false,
      message: 'Invalid dateTo format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss)',
    };
    res.status(400).json(response);
    return;
  }
  
  if (dateFrom && dateTo) {
    const fromDate = new Date(dateFrom as string);
    const toDate = new Date(dateTo as string);
    
    if (fromDate > toDate) {
      const response: ApiResponse = {
        success: false,
        message: 'dateFrom cannot be later than dateTo',
      };
      res.status(400).json(response);
      return;
    }
  }
  
  next();
};
