import express from 'express';
import { analyticsController } from '../controllers/analyticsController';
import { authenticate, authorize } from '../middlewares/auth';
import { validateDateRange, validatePagination } from '../middlewares/validation';

const router = express.Router();

// Dashboard analytics
router.get('/dashboard',
  authenticate,
  authorize(['analytics:read']),
  validateDateRange,
  analyticsController.getDashboardAnalytics
);

// Violation trends
router.get('/violations/trends',
  authenticate,
  authorize(['analytics:read']),
  validateDateRange,
  analyticsController.getViolationTrends
);

// Vehicle scan analytics
router.get('/scans/analytics',
  authenticate,
  authorize(['analytics:read']),
  validateDateRange,
  analyticsController.getScanAnalytics
);

// User activity analytics
router.get('/users/activity',
  authenticate,
  authorize(['analytics:read']),
  validateDateRange,
  analyticsController.getUserActivityAnalytics
);

// Performance metrics
router.get('/performance',
  authenticate,
  authorize(['analytics:read']),
  validateDateRange,
  analyticsController.getPerformanceMetrics
);

// Geographic data
router.get('/geographic',
  authenticate,
  authorize(['analytics:read']),
  validateDateRange,
  analyticsController.getGeographicData
);

export default router;
