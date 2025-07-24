import jwt from 'jsonwebtoken';
import { JWTPayload } from '../types';
import { logger } from './logger';

const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

export const generateToken = (payload: Omit<JWTPayload, 'iat' | 'exp'>): string => {
  try {
    return jwt.sign(payload, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
      issuer: 'plate-recognition-system',
      audience: 'plate-recognition-users',
    });
  } catch (error) {
    logger.error('Error generating JWT token:', error);
    throw new Error('Token generation failed');
  }
};

export const verifyToken = (token: string): JWTPayload => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'plate-recognition-system',
      audience: 'plate-recognition-users',
    }) as JWTPayload;
    
    return decoded;
  } catch (error) {
    logger.error('Error verifying JWT token:', error);
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Token has expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid token');
    } else {
      throw new Error('Token verification failed');
    }
  }
};

export const refreshToken = (token: string): string => {
  try {
    // Verify the existing token (this will throw if expired)
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'plate-recognition-system',
      audience: 'plate-recognition-users',
      ignoreExpiration: true, // Allow expired tokens for refresh
    }) as JWTPayload;

    // Create a new token with the same payload (excluding exp and iat)
    const newPayload: Omit<JWTPayload, 'iat' | 'exp'> = {
      userId: decoded.userId,
      username: decoded.username,
      email: decoded.email,
      roleId: decoded.roleId,
      accountType: decoded.accountType,
    };

    return generateToken(newPayload);
  } catch (error) {
    logger.error('Error refreshing JWT token:', error);
    throw new Error('Token refresh failed');
  }
};

export const getTokenPayload = (token: string): JWTPayload | null => {
  try {
    const decoded = jwt.decode(token) as JWTPayload;
    return decoded;
  } catch (error) {
    logger.error('Error decoding JWT token:', error);
    return null;
  }
};

export const isTokenExpired = (token: string): boolean => {
  try {
    const decoded = getTokenPayload(token);
    if (!decoded || !decoded.exp) {
      return true;
    }
    
    const currentTime = Math.floor(Date.now() / 1000);
    return decoded.exp < currentTime;
  } catch (error) {
    return true;
  }
};

export const getTokenExpirationDate = (token: string): Date | null => {
  try {
    const decoded = getTokenPayload(token);
    if (!decoded || !decoded.exp) {
      return null;
    }
    
    return new Date(decoded.exp * 1000);
  } catch (error) {
    return null;
  }
};
