import express from 'express';
import { body } from 'express-validator';
import { violationController } from '../controllers/violationController';
import { authenticate, authorize } from '../middlewares/auth';
import { validateRequest, validatePagination, validateIdParam, validateDateRange } from '../middlewares/validation';

const router = express.Router();

// Validation rules
const createViolationValidation = [
  body('plateNumber')
    .notEmpty()
    .withMessage('Plate number is required'),
  body('violationType')
    .isIn(['SPEEDING', 'PARKING', 'RED_LIGHT', 'ILLEGAL_TURN', 'NO_INSURANCE', 'EXPIRED_REGISTRATION', 'RECKLESS_DRIVING', 'DUI', 'OTHER'])
    .withMessage('Invalid violation type'),
  body('description')
    .notEmpty()
    .withMessage('Description is required'),
  body('location')
    .notEmpty()
    .withMessage('Location is required'),
  body('violationDate')
    .isISO8601()
    .withMessage('Invalid violation date'),
  body('fineAmount')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Fine amount must be a positive number'),
];

// Routes

// Get all violations
router.get('/',
  authenticate,
  authorize(['violations:read']),
  validatePagination,
  validateDateRange,
  violationController.getViolations
);

// Get violation by ID
router.get('/:id',
  authenticate,
  authorize(['violations:read']),
  validateIdParam('id'),
  violationController.getViolationById
);

// Create new violation
router.post('/',
  authenticate,
  authorize(['violations:create']),
  createViolationValidation,
  validateRequest,
  violationController.createViolation
);

// Update violation
router.put('/:id',
  authenticate,
  authorize(['violations:update']),
  validateIdParam('id'),
  violationController.updateViolation
);

// Delete violation
router.delete('/:id',
  authenticate,
  authorize(['violations:delete']),
  validateIdParam('id'),
  violationController.deleteViolation
);

// Update violation status
router.patch('/:id/status',
  authenticate,
  authorize(['violations:update']),
  validateIdParam('id'),
  body('status').isIn(['PENDING', 'CONFIRMED', 'DISPUTED', 'RESOLVED', 'DISMISSED', 'PAID']).withMessage('Invalid status'),
  validateRequest,
  violationController.updateViolationStatus
);

// Process payment
router.post('/:id/payment',
  authenticate,
  authorize(['violations:update']),
  validateIdParam('id'),
  body('amount').isFloat({ min: 0 }).withMessage('Invalid payment amount'),
  body('paymentMethod').notEmpty().withMessage('Payment method is required'),
  validateRequest,
  violationController.processPayment
);

// Get violation statistics
router.get('/stats/overview',
  authenticate,
  authorize(['violations:read']),
  validateDateRange,
  violationController.getViolationStats
);

export default router;
