import express from 'express';
import { body } from 'express-validator';
import multer from 'multer';
import { plateRecognitionController } from '../controllers/plateRecognitionController';
import { authenticate, authorize } from '../middlewares/auth';
import { validateRequest, validatePagination } from '../middlewares/validation';

const router = express.Router();

// Configure multer for file uploads
const upload = multer({
  dest: 'uploads/temp/',
  limits: {
    fileSize: parseInt(process.env.UPLOAD_MAX_SIZE || '10485760'), // 10MB
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  },
});

// Validation rules
const scanValidation = [
  body('location')
    .optional()
    .notEmpty()
    .withMessage('Location cannot be empty'),
  body('coordinates')
    .optional()
    .matches(/^-?\d+\.?\d*,-?\d+\.?\d*$/)
    .withMessage('Invalid coordinates format (latitude,longitude)'),
  body('cameraId')
    .optional()
    .notEmpty()
    .withMessage('Camera ID cannot be empty'),
];

// Routes

// Scan image for plate recognition
router.post('/scan',
  authenticate,
  authorize(['plate-recognition:scan']),
  upload.single('image'),
  scanValidation,
  validateRequest,
  plateRecognitionController.scanPlate
);

// Scan image from base64
router.post('/scan-base64',
  authenticate,
  authorize(['plate-recognition:scan']),
  body('imageBase64').notEmpty().withMessage('Base64 image data is required'),
  scanValidation,
  validateRequest,
  plateRecognitionController.scanPlateBase64
);

// Get scan history
router.get('/scans',
  authenticate,
  authorize(['plate-recognition:read']),
  validatePagination,
  plateRecognitionController.getScanHistory
);

// Get scan by ID
router.get('/scans/:id',
  authenticate,
  authorize(['plate-recognition:read']),
  plateRecognitionController.getScanById
);

// Batch scan multiple images
router.post('/batch-scan',
  authenticate,
  authorize(['plate-recognition:scan']),
  upload.array('images', 10), // Max 10 images
  plateRecognitionController.batchScan
);

// Get plate recognition statistics
router.get('/stats',
  authenticate,
  authorize(['plate-recognition:read']),
  plateRecognitionController.getStats
);

// Test OCR service
router.get('/test',
  authenticate,
  authorize(['plate-recognition:scan']),
  plateRecognitionController.testOCRService
);

export default router;
