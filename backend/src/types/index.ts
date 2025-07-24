import { Request } from 'express';
import { User, Role } from '@prisma/client';

// Extend Express Request interface
export interface AuthenticatedRequest extends Request {
  user?: User & {
    role: Role;
  };
}

// API Response interfaces
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  errors?: any[];
  meta?: {
    total?: number;
    page?: number;
    limit?: number;
    totalPages?: number;
  };
}

export interface PaginationQuery {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface SearchQuery extends PaginationQuery {
  search?: string;
  filter?: Record<string, any>;
}

// User-related types
export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
  accountType: 'POLICE' | 'DVLA' | 'ADMINISTRATOR';
  roleId: string;
  badgeNumber?: string;
  rank?: string;
  station?: string;
  idNumber?: string;
  position?: string;
  department?: string;
}

export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  email?: string;
  phoneNumber?: string;
  isActive?: boolean;
  roleId?: string;
  badgeNumber?: string;
  rank?: string;
  station?: string;
  idNumber?: string;
  position?: string;
  department?: string;
}

export interface UserApprovalRequest {
  userId: string;
  action: 'approve' | 'reject';
  reason?: string;
}

// Vehicle-related types
export interface CreateVehicleRequest {
  plateNumber: string;
  make: string;
  model: string;
  year: number;
  color: string;
  vin?: string;
  engineNumber?: string;
  registrationDate: Date;
  expiryDate?: Date;
  vehicleType: 'CAR' | 'MOTORCYCLE' | 'TRUCK' | 'BUS' | 'VAN' | 'TRAILER' | 'OTHER';
  fuelType?: string;
  ownerId: string;
  ownerAddress: string;
  ownerCity: string;
  ownerState: string;
  ownerPostalCode: string;
  insuranceNumber?: string;
  insuranceExpiry?: Date;
  insuranceProvider?: string;
}

export interface UpdateVehicleRequest {
  make?: string;
  model?: string;
  year?: number;
  color?: string;
  vin?: string;
  engineNumber?: string;
  expiryDate?: Date;
  status?: 'ACTIVE' | 'EXPIRED' | 'SUSPENDED' | 'STOLEN' | 'IMPOUNDED';
  vehicleType?: 'CAR' | 'MOTORCYCLE' | 'TRUCK' | 'BUS' | 'VAN' | 'TRAILER' | 'OTHER';
  fuelType?: string;
  ownerId?: string;
  ownerAddress?: string;
  ownerCity?: string;
  ownerState?: string;
  ownerPostalCode?: string;
  insuranceNumber?: string;
  insuranceExpiry?: Date;
  insuranceProvider?: string;
}

// Violation-related types
export interface CreateViolationRequest {
  plateNumber: string;
  violationType: 'SPEEDING' | 'PARKING' | 'RED_LIGHT' | 'ILLEGAL_TURN' | 'NO_INSURANCE' | 'EXPIRED_REGISTRATION' | 'RECKLESS_DRIVING' | 'DUI' | 'OTHER';
  description: string;
  location: string;
  coordinates?: string;
  fineAmount?: number;
  violationDate: Date;
  dueDate?: Date;
  images?: string[];
  videoUrl?: string;
  evidenceNotes?: string;
  issuedById?: string;
}

export interface UpdateViolationRequest {
  violationType?: 'SPEEDING' | 'PARKING' | 'RED_LIGHT' | 'ILLEGAL_TURN' | 'NO_INSURANCE' | 'EXPIRED_REGISTRATION' | 'RECKLESS_DRIVING' | 'DUI' | 'OTHER';
  description?: string;
  location?: string;
  coordinates?: string;
  fineAmount?: number;
  status?: 'PENDING' | 'CONFIRMED' | 'DISPUTED' | 'RESOLVED' | 'DISMISSED' | 'PAID';
  dueDate?: Date;
  images?: string[];
  videoUrl?: string;
  evidenceNotes?: string;
  paidAmount?: number;
  paidAt?: Date;
  paymentMethod?: string;
  receiptNumber?: string;
}

// Plate Recognition types
export interface PlateRecognitionRequest {
  imageUrl?: string;
  imageBase64?: string;
  location?: string;
  coordinates?: string;
  cameraId?: string;
  scannerId?: string;
}

export interface PlateRecognitionResult {
  plateNumber: string;
  confidence: number;
  boundingBox?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  isViolation: boolean;
  violationTypes: string[];
  vehicleInfo?: {
    make?: string;
    model?: string;
    year?: number;
    color?: string;
    status?: string;
  };
}

// Report types
export interface CreateReportRequest {
  title: string;
  type: 'VIOLATION_SUMMARY' | 'VEHICLE_REGISTRY' | 'USER_ACTIVITY' | 'DAILY_SCAN' | 'QUARTERLY_SUMMARY' | 'PERFORMANCE_METRICS' | 'AUDIT_TRAIL';
  description?: string;
  parameters?: Record<string, any>;
  dateFrom?: Date;
  dateTo?: Date;
}

// Analytics types
export interface AnalyticsQuery {
  dateFrom?: Date;
  dateTo?: Date;
  groupBy?: 'day' | 'week' | 'month' | 'year';
  filters?: Record<string, any>;
}

export interface AnalyticsResult {
  total: number;
  period: string;
  data: Array<{
    date: string;
    value: number;
    label?: string;
  }>;
  summary?: Record<string, number>;
}

// File upload types
export interface FileUploadResult {
  filename: string;
  originalName: string;
  size: number;
  mimeType: string;
  url: string;
}

// JWT Payload
export interface JWTPayload {
  userId: string;
  username: string;
  email: string;
  roleId: string;
  accountType: string;
  iat?: number;
  exp?: number;
}

// Permission types
export interface Permission {
  resource: string;
  action: string;
}

// Audit log types
export interface AuditLogData {
  action: 'CREATE' | 'READ' | 'UPDATE' | 'DELETE' | 'LOGIN' | 'LOGOUT' | 'APPROVE' | 'REJECT' | 'EXPORT';
  resource: string;
  resourceId?: string;
  oldValues?: Record<string, any>;
  newValues?: Record<string, any>;
  description?: string;
  ipAddress?: string;
  userAgent?: string;
}

// System settings types
export interface SystemSetting {
  key: string;
  value: string;
  description?: string;
  isPublic?: boolean;
}

// Error types
export interface ApiError extends Error {
  statusCode: number;
  isOperational: boolean;
  code?: string;
}

// Email types
export interface EmailOptions {
  to: string;
  subject: string;
  template: string;
  data: Record<string, any>;
}

// Statistics types
export interface DashboardStats {
  totalVehicles: number;
  totalViolations: number;
  activeViolations: number;
  resolvedViolations: number;
  totalUsers: number;
  pendingApprovals: number;
  todayScans: number;
  monthlyGrowth: number;
}

// Notification types
export interface NotificationData {
  type: 'USER_REGISTRATION' | 'VIOLATION_CREATED' | 'PAYMENT_RECEIVED' | 'SYSTEM_ALERT';
  title: string;
  message: string;
  userId?: string;
  data?: Record<string, any>;
}
