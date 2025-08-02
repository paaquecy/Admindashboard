import express from 'express';
import { body, query } from 'express-validator';
import { userController } from '../controllers/userController';
import { authenticate, authorize, requireAccountType } from '../middlewares/auth';
import { validateRequest, validatePagination, validateIdParam } from '../middlewares/validation';

const router = express.Router();

// Validation rules
const createUserValidation = [
  body('username')
    .notEmpty()
    .withMessage('Username is required')
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters'),
  body('email')
    .isEmail()
    .withMessage('Valid email is required')
    .normalizeEmail(),
  body('firstName')
    .notEmpty()
    .withMessage('First name is required'),
  body('lastName')
    .notEmpty()
    .withMessage('Last name is required'),
  body('accountType')
    .isIn(['POLICE', 'DVLA', 'ADMINISTRATOR'])
    .withMessage('Invalid account type'),
  body('roleId')
    .notEmpty()
    .withMessage('Role ID is required'),
];

const updateUserValidation = [
  body('email')
    .optional()
    .isEmail()
    .withMessage('Valid email is required')
    .normalizeEmail(),
  body('firstName')
    .optional()
    .notEmpty()
    .withMessage('First name cannot be empty'),
  body('lastName')
    .optional()
    .notEmpty()
    .withMessage('Last name cannot be empty'),
];

const approvalValidation = [
  body('action')
    .isIn(['approve', 'reject'])
    .withMessage('Action must be either approve or reject'),
  body('reason')
    .if(body('action').equals('reject'))
    .notEmpty()
    .withMessage('Reason is required when rejecting a user'),
];

// Routes

// Get all users (with pagination, search, filtering)
router.get('/',
  authenticate,
  authorize(['users:read']),
  validatePagination,
  userController.getUsers
);

// Get pending user approvals
router.get('/pending',
  authenticate,
  authorize(['users:approve']),
  validatePagination,
  userController.getPendingUsers
);

// Get user by ID
router.get('/:id',
  authenticate,
  authorize(['users:read']),
  validateIdParam('id'),
  userController.getUserById
);

// Create new user (admin only)
router.post('/',
  authenticate,
  authorize(['users:create']),
  createUserValidation,
  validateRequest,
  userController.createUser
);

// Update user
router.put('/:id',
  authenticate,
  authorize(['users:update']),
  validateIdParam('id'),
  updateUserValidation,
  validateRequest,
  userController.updateUser
);

// Delete user
router.delete('/:id',
  authenticate,
  authorize(['users:delete']),
  validateIdParam('id'),
  userController.deleteUser
);

// Approve or reject user
router.post('/:id/approval',
  authenticate,
  authorize(['users:approve']),
  validateIdParam('id'),
  approvalValidation,
  validateRequest,
  userController.approveUser
);

// Suspend/unsuspend user
router.patch('/:id/status',
  authenticate,
  authorize(['users:update']),
  validateIdParam('id'),
  body('status').isIn(['APPROVED', 'SUSPENDED', 'INACTIVE']).withMessage('Invalid status'),
  validateRequest,
  userController.updateUserStatus
);

// Reset user password (admin only)
router.post('/:id/reset-password',
  authenticate,
  authorize(['users:update']),
  validateIdParam('id'),
  userController.resetUserPassword
);

// Get user activity logs
router.get('/:id/activity',
  authenticate,
  authorize(['users:read']),
  validateIdParam('id'),
  validatePagination,
  userController.getUserActivity
);

// Get user statistics
router.get('/stats/overview',
  authenticate,
  authorize(['users:read']),
  userController.getUserStats
);

export default router;
