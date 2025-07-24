import express from 'express';
import { body } from 'express-validator';
import { reportController } from '../controllers/reportController';
import { authenticate, authorize } from '../middlewares/auth';
import { validateRequest, validatePagination, validateIdParam, validateDateRange } from '../middlewares/validation';

const router = express.Router();

// Validation rules
const createReportValidation = [
  body('title')
    .notEmpty()
    .withMessage('Report title is required'),
  body('type')
    .isIn(['VIOLATION_SUMMARY', 'VEHICLE_REGISTRY', 'USER_ACTIVITY', 'DAILY_SCAN', 'QUARTERLY_SUMMARY', 'PERFORMANCE_METRICS', 'AUDIT_TRAIL'])
    .withMessage('Invalid report type'),
  body('dateFrom')
    .optional()
    .isISO8601()
    .withMessage('Invalid date format for dateFrom'),
  body('dateTo')
    .optional()
    .isISO8601()
    .withMessage('Invalid date format for dateTo'),
];

// Routes

// Get all reports
router.get('/',
  authenticate,
  authorize(['reports:read']),
  validatePagination,
  reportController.getReports
);

// Get report by ID
router.get('/:id',
  authenticate,
  authorize(['reports:read']),
  validateIdParam('id'),
  reportController.getReportById
);

// Create new report
router.post('/',
  authenticate,
  authorize(['reports:create']),
  createReportValidation,
  validateRequest,
  reportController.createReport
);

// Download report
router.get('/:id/download',
  authenticate,
  authorize(['reports:read']),
  validateIdParam('id'),
  reportController.downloadReport
);

// Delete report
router.delete('/:id',
  authenticate,
  authorize(['reports:delete']),
  validateIdParam('id'),
  reportController.deleteReport
);

// Generate quick reports
router.post('/quick/violations',
  authenticate,
  authorize(['reports:create']),
  validateDateRange,
  reportController.generateQuickViolationReport
);

router.post('/quick/vehicles',
  authenticate,
  authorize(['reports:create']),
  reportController.generateQuickVehicleReport
);

router.post('/quick/users',
  authenticate,
  authorize(['reports:create']),
  reportController.generateQuickUserReport
);

// Export data
router.post('/export/csv',
  authenticate,
  authorize(['reports:export']),
  body('type').isIn(['violations', 'vehicles', 'users', 'scans']).withMessage('Invalid export type'),
  validateRequest,
  reportController.exportToCSV
);

router.post('/export/pdf',
  authenticate,
  authorize(['reports:export']),
  body('type').isIn(['violations', 'vehicles', 'users']).withMessage('Invalid export type'),
  validateRequest,
  reportController.exportToPDF
);

export default router;
