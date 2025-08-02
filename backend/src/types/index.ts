import { Request } from 'express';
import { User, Role, Permission } from '@prisma/client';

// ================================
// REQUEST INTERFACES
// ================================

export interface AuthenticatedRequest extends Request {
  user?: User & {
    role: Role & {
      permissions: Permission[];
    };
  };
  sessionId?: string;
}

// ================================
// API RESPONSE INTERFACES
// ================================

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
    hasNextPage?: boolean;
    hasPrevPage?: boolean;
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

// ================================
// USER MANAGEMENT TYPES
// ================================

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
  action: 'approve' | 'reject';
  reason?: string;
}

export interface PasswordChangeRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface TwoFactorSetupRequest {
  enabled: boolean;
  token?: string;
}

// ================================
// VEHICLE MANAGEMENT TYPES
// ================================

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
  vehicleType: 'CAR' | 'MOTORCYCLE' | 'TRUCK' | 'BUS' | 'VAN' | 'TRAILER' | 'BICYCLE' | 'OTHER';
  fuelType?: string;
  ownerId: string;
  ownerAddress: string;
  ownerCity: string;
  ownerState: string;
  ownerPostalCode: string;
  ownerCountry?: string;
  insuranceNumber?: string;
  insuranceExpiry?: Date;
  insuranceProvider?: string;
  motExpiry?: Date;
  taxExpiry?: Date;
}

export interface UpdateVehicleRequest {
  make?: string;
  model?: string;
  year?: number;
  color?: string;
  vin?: string;
  engineNumber?: string;
  expiryDate?: Date;
  status?: 'ACTIVE' | 'EXPIRED' | 'SUSPENDED' | 'STOLEN' | 'IMPOUNDED' | 'SCRAPPED';
  vehicleType?: 'CAR' | 'MOTORCYCLE' | 'TRUCK' | 'BUS' | 'VAN' | 'TRAILER' | 'BICYCLE' | 'OTHER';
  fuelType?: string;
  ownerId?: string;
  ownerAddress?: string;
  ownerCity?: string;
  ownerState?: string;
  ownerPostalCode?: string;
  ownerCountry?: string;
  insuranceNumber?: string;
  insuranceExpiry?: Date;
  insuranceProvider?: string;
  motExpiry?: Date;
  taxExpiry?: Date;
}

export interface VehicleSearchFilters {
  plateNumber?: string;
  make?: string;
  model?: string;
  year?: number;
  color?: string;
  status?: string;
  ownerId?: string;
  expiryFrom?: Date;
  expiryTo?: Date;
}

// ================================
// VIOLATION MANAGEMENT TYPES
// ================================

export interface CreateViolationRequest {
  plateNumber: string;
  violationType: 'SPEEDING' | 'PARKING' | 'RED_LIGHT' | 'ILLEGAL_TURN' | 'NO_INSURANCE' | 'EXPIRED_REGISTRATION' | 'RECKLESS_DRIVING' | 'DUI' | 'MOBILE_PHONE' | 'SEATBELT' | 'EMISSIONS' | 'OVERWEIGHT' | 'OTHER';
  description: string;
  location: string;
  coordinates?: string;
  fineAmount?: number;
  violationDate: Date;
  dueDate?: Date;
  images?: string[];
  videoUrl?: string;
  evidenceNotes?: string;
  witnessDetails?: string;
  issuedById?: string;
}

export interface UpdateViolationRequest {
  violationType?: 'SPEEDING' | 'PARKING' | 'RED_LIGHT' | 'ILLEGAL_TURN' | 'NO_INSURANCE' | 'EXPIRED_REGISTRATION' | 'RECKLESS_DRIVING' | 'DUI' | 'MOBILE_PHONE' | 'SEATBELT' | 'EMISSIONS' | 'OVERWEIGHT' | 'OTHER';
  description?: string;
  location?: string;
  coordinates?: string;
  fineAmount?: number;
  status?: 'PENDING' | 'CONFIRMED' | 'DISPUTED' | 'RESOLVED' | 'DISMISSED' | 'PAID' | 'OVERDUE';
  dueDate?: Date;
  images?: string[];
  videoUrl?: string;
  evidenceNotes?: string;
  witnessDetails?: string;
  paidAmount?: number;
  paidAt?: Date;
  paymentMethod?: string;
  receiptNumber?: string;
}

export interface ViolationFilters {
  plateNumber?: string;
  violationType?: string;
  status?: string;
  location?: string;
  dateFrom?: Date;
  dateTo?: Date;
  issuedById?: string;
  minAmount?: number;
  maxAmount?: number;
}

export interface PaymentRequest {
  amount: number;
  paymentMethod: string;
  receiptNumber?: string;
  notes?: string;
}

export interface AppealRequest {
  reason: string;
  evidence?: string[];
  witnessDetails?: string;
}

// ================================
// PLATE RECOGNITION TYPES
// ================================

export interface PlateRecognitionRequest {
  imageUrl?: string;
  imageBase64?: string;
  location?: string;
  coordinates?: string;
  cameraId?: string;
  scannerId?: string;
  scannerType?: string;
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
  processingTime?: number;
  imageQuality?: string;
  weatherConditions?: string;
  timeOfDay?: string;
}

export interface BatchScanRequest {
  images: Express.Multer.File[];
  location?: string;
  coordinates?: string;
  cameraId?: string;
  scannerId?: string;
}

// ================================
// REPORTING TYPES
// ================================

export interface CreateReportRequest {
  title: string;
  type: 'VIOLATION_SUMMARY' | 'VEHICLE_REGISTRY' | 'USER_ACTIVITY' | 'DAILY_SCAN' | 'WEEKLY_SUMMARY' | 'MONTHLY_SUMMARY' | 'QUARTERLY_SUMMARY' | 'ANNUAL_SUMMARY' | 'PERFORMANCE_METRICS' | 'AUDIT_TRAIL' | 'FINANCIAL_REPORT' | 'COMPLIANCE_REPORT';
  description?: string;
  parameters?: Record<string, any>;
  dateFrom?: Date;
  dateTo?: Date;
}

export interface ReportFilters {
  type?: string;
  status?: string;
  createdBy?: string;
  dateFrom?: Date;
  dateTo?: Date;
}

export interface ExportRequest {
  type: 'violations' | 'vehicles' | 'users' | 'scans' | 'audit';
  format: 'csv' | 'pdf' | 'excel' | 'json';
  filters?: Record<string, any>;
  dateFrom?: Date;
  dateTo?: Date;
}

// ================================
// ANALYTICS TYPES
// ================================

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

export interface DashboardStats {
  totalVehicles: number;
  totalViolations: number;
  activeViolations: number;
  resolvedViolations: number;
  totalUsers: number;
  pendingApprovals: number;
  todayScans: number;
  monthlyGrowth: number;
  recentActivities: Array<{
    description: string;
    time: string;
    type: string;
  }>;
  upcomingDeadlines: Array<{
    violationId: string;
    plateNumber: string;
    dueDate: string;
  }>;
  performanceMetrics: {
    averageProcessingTime: number;
    scanAccuracy: number;
    systemUptime: number;
  };
}

// ================================
// SYSTEM MANAGEMENT TYPES
// ================================

export interface SystemSetting {
  key: string;
  value: string;
  description?: string;
  category?: string;
  isPublic?: boolean;
  isEncrypted?: boolean;
  validationRegex?: string;
}

export interface SystemHealthCheck {
  service: string;
  status: 'healthy' | 'degraded' | 'down';
  responseTime?: number;
  lastChecked: Date;
  errorMessage?: string;
}

export interface BackupRequest {
  type: 'FULL' | 'INCREMENTAL' | 'LOGS_ONLY';
  description?: string;
}

// ================================
// NOTIFICATION TYPES
// ================================

export interface NotificationData {
  type: 'USER_REGISTRATION' | 'VIOLATION_CREATED' | 'PAYMENT_RECEIVED' | 'APPEAL_SUBMITTED' | 'SYSTEM_ALERT' | 'SECURITY_WARNING' | 'REPORT_READY' | 'ACCOUNT_LOCKED' | 'PASSWORD_CHANGED';
  title: string;
  message: string;
  userId?: string;
  data?: Record<string, any>;
  expiresAt?: Date;
}

// ================================
// AUDIT TYPES
// ================================

export interface AuditLogData {
  action: 'CREATE' | 'READ' | 'UPDATE' | 'DELETE' | 'LOGIN' | 'LOGOUT' | 'APPROVE' | 'REJECT' | 'EXPORT' | 'BACKUP' | 'RESTORE' | 'SCAN' | 'PAYMENT' | 'APPEAL';
  resource: string;
  resourceId?: string;
  oldValues?: Record<string, any>;
  newValues?: Record<string, any>;
  description?: string;
  ipAddress?: string;
  userAgent?: string;
  location?: string;
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  suspicious?: boolean;
}

export interface AuditFilters {
  userId?: string;
  resource?: string;
  action?: string;
  riskLevel?: string;
  dateFrom?: Date;
  dateTo?: Date;
  suspicious?: boolean;
}

// ================================
// FILE UPLOAD TYPES
// ================================

export interface FileUploadResult {
  filename: string;
  originalName: string;
  size: number;
  mimeType: string;
  url: string;
  path: string;
}

export interface ImageProcessingOptions {
  resize?: {
    width: number;
    height: number;
  };
  quality?: number;
  format?: 'jpeg' | 'png' | 'webp';
}

// ================================
// JWT TYPES
// ================================

export interface JWTPayload {
  userId: string;
  username: string;
  email: string;
  roleId: string;
  accountType: string;
  sessionId: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  userId: string;
  sessionId: string;
  iat?: number;
  exp?: number;
}

// ================================
// EMAIL TYPES
// ================================

export interface EmailOptions {
  to: string | string[];
  subject: string;
  template: string;
  data: Record<string, any>;
  attachments?: Array<{
    filename: string;
    path: string;
  }>;
}

export interface EmailTemplate {
  subject: string;
  html: string;
  text?: string;
}

// ================================
// ERROR TYPES
// ================================

export interface ApiError extends Error {
  statusCode: number;
  isOperational: boolean;
  code?: string;
  details?: any;
}

export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

// ================================
// CACHE TYPES
// ================================

export interface CacheOptions {
  ttl?: number; // Time to live in seconds
  tags?: string[]; // Cache tags for invalidation
}

export interface CacheManager {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, options?: CacheOptions): Promise<void>;
  del(key: string): Promise<void>;
  delByTags(tags: string[]): Promise<void>;
  clear(): Promise<void>;
}

// ================================
// ROLE AND PERMISSION TYPES
// ================================

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissionIds: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permissionIds?: string[];
  isActive?: boolean;
}

export interface PermissionCheck {
  resource: string;
  action: string;
}

// ================================
// STATISTICS TYPES
// ================================

export interface StatisticsQuery {
  dateFrom?: Date;
  dateTo?: Date;
  groupBy?: 'hour' | 'day' | 'week' | 'month' | 'year';
  filters?: Record<string, any>;
}

export interface TimeSeriesData {
  timestamp: Date;
  value: number;
  metadata?: Record<string, any>;
}

export interface AggregatedStats {
  total: number;
  average: number;
  minimum: number;
  maximum: number;
  growth: number;
  trend: 'up' | 'down' | 'stable';
}
