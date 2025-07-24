import express from 'express';
import { body } from 'express-validator';
import { vehicleController } from '../controllers/vehicleController';
import { authenticate, authorize } from '../middlewares/auth';
import { validateRequest, validatePagination, validateIdParam } from '../middlewares/validation';

const router = express.Router();

// Validation rules
const createVehicleValidation = [
  body('plateNumber')
    .notEmpty()
    .withMessage('Plate number is required')
    .matches(/^[A-Z0-9-]+$/)
    .withMessage('Invalid plate number format'),
  body('make')
    .notEmpty()
    .withMessage('Vehicle make is required'),
  body('model')
    .notEmpty()
    .withMessage('Vehicle model is required'),
  body('year')
    .isInt({ min: 1900, max: new Date().getFullYear() + 1 })
    .withMessage('Invalid year'),
  body('color')
    .notEmpty()
    .withMessage('Vehicle color is required'),
  body('vehicleType')
    .isIn(['CAR', 'MOTORCYCLE', 'TRUCK', 'BUS', 'VAN', 'TRAILER', 'OTHER'])
    .withMessage('Invalid vehicle type'),
  body('ownerId')
    .notEmpty()
    .withMessage('Owner ID is required'),
  body('ownerAddress')
    .notEmpty()
    .withMessage('Owner address is required'),
  body('ownerCity')
    .notEmpty()
    .withMessage('Owner city is required'),
  body('ownerState')
    .notEmpty()
    .withMessage('Owner state is required'),
  body('ownerPostalCode')
    .notEmpty()
    .withMessage('Owner postal code is required'),
];

// Routes

// Get all vehicles
router.get('/',
  authenticate,
  authorize(['vehicles:read']),
  validatePagination,
  vehicleController.getVehicles
);

// Search vehicles by plate number
router.get('/search',
  authenticate,
  authorize(['vehicles:read']),
  vehicleController.searchVehicles
);

// Get vehicle by ID
router.get('/:id',
  authenticate,
  authorize(['vehicles:read']),
  validateIdParam('id'),
  vehicleController.getVehicleById
);

// Get vehicle by plate number
router.get('/plate/:plateNumber',
  authenticate,
  authorize(['vehicles:read']),
  vehicleController.getVehicleByPlate
);

// Create new vehicle
router.post('/',
  authenticate,
  authorize(['vehicles:create']),
  createVehicleValidation,
  validateRequest,
  vehicleController.createVehicle
);

// Update vehicle
router.put('/:id',
  authenticate,
  authorize(['vehicles:update']),
  validateIdParam('id'),
  vehicleController.updateVehicle
);

// Delete vehicle
router.delete('/:id',
  authenticate,
  authorize(['vehicles:delete']),
  validateIdParam('id'),
  vehicleController.deleteVehicle
);

// Get vehicle violations
router.get('/:id/violations',
  authenticate,
  authorize(['violations:read']),
  validateIdParam('id'),
  validatePagination,
  vehicleController.getVehicleViolations
);

// Get vehicle scan history
router.get('/:id/scans',
  authenticate,
  authorize(['vehicles:read']),
  validateIdParam('id'),
  validatePagination,
  vehicleController.getVehicleScans
);

// Get vehicle statistics
router.get('/stats/overview',
  authenticate,
  authorize(['vehicles:read']),
  vehicleController.getVehicleStats
);

export default router;
