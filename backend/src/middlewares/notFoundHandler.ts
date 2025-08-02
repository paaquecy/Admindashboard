import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '../types';

export const notFoundHandler = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const response: ApiResponse = {
    success: false,
    message: `Endpoint ${req.method} ${req.originalUrl} not found`,
    data: null,
  };

  res.status(404).json(response);
};
