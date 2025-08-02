import express from 'express';
import { body } from 'express-validator';
import { authController } from '../controllers/authController';
import { authenticate } from '../middlewares/auth';
import { validateRequest } from '../middlewares/validation';

const router = express.Router();

// Validation rules
const loginValidation = [
  body('username')
    .notEmpty()
    .withMessage('Username is required')
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('twoFactorToken')
    .optional()
    .isLength({ min: 6, max: 6 })
    .withMessage('Two-factor token must be 6 digits')
    .isNumeric()
    .withMessage('Two-factor token must be numeric'),
];

const registerValidation = [
  body('username')
    .notEmpty()
    .withMessage('Username is required')
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .withMessage('Valid email is required')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('firstName')
    .notEmpty()
    .withMessage('First name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),
  body('lastName')
    .notEmpty()
    .withMessage('Last name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),
  body('phoneNumber')
    .optional()
    .isMobilePhone('any')
    .withMessage('Valid phone number is required'),
  body('accountType')
    .isIn(['POLICE', 'DVLA'])
    .withMessage('Account type must be either POLICE or DVLA'),
  body('badgeNumber')
    .if(body('accountType').equals('POLICE'))
    .notEmpty()
    .withMessage('Badge number is required for police officers'),
  body('rank')
    .if(body('accountType').equals('POLICE'))
    .notEmpty()
    .withMessage('Rank is required for police officers'),
  body('station')
    .if(body('accountType').equals('POLICE'))
    .notEmpty()
    .withMessage('Station is required for police officers'),
  body('idNumber')
    .if(body('accountType').equals('DVLA'))
    .notEmpty()
    .withMessage('ID number is required for DVLA officers'),
  body('position')
    .if(body('accountType').equals('DVLA'))
    .notEmpty()
    .withMessage('Position is required for DVLA officers'),
];

const changePasswordValidation = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    }),
];

const twoFactorValidation = [
  body('enabled')
    .isBoolean()
    .withMessage('Enabled must be a boolean value'),
  body('token')
    .optional()
    .isLength({ min: 6, max: 6 })
    .withMessage('Token must be 6 digits')
    .isNumeric()
    .withMessage('Token must be numeric'),
];

const refreshTokenValidation = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required'),
];

// Authentication routes
router.post('/login', 
  loginValidation, 
  validateRequest, 
  authController.login
);

router.post('/register', 
  registerValidation, 
  validateRequest, 
  authController.register
);

router.post('/logout', 
  authenticate, 
  authController.logout
);

router.post('/refresh', 
  refreshTokenValidation, 
  validateRequest, 
  authController.refreshToken
);

router.post('/change-password', 
  authenticate, 
  changePasswordValidation, 
  validateRequest, 
  authController.changePassword
);

router.post('/two-factor', 
  authenticate, 
  twoFactorValidation, 
  validateRequest, 
  authController.setupTwoFactor
);

router.get('/profile', 
  authenticate, 
  authController.getProfile
);

router.put('/profile', 
  authenticate, 
  authController.updateProfile
);

router.post('/forgot-password', 
  body('email').isEmail().withMessage('Valid email is required'),
  validateRequest, 
  authController.forgotPassword
);

router.post('/reset-password', 
  body('token').notEmpty().withMessage('Reset token is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  validateRequest, 
  authController.resetPassword
);

router.get('/verify-email/:token', 
  authController.verifyEmail
);

router.post('/resend-verification', 
  authenticate, 
  authController.resendVerification
);

export default router;
