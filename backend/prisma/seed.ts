import { PrismaClient } from '@prisma/client';
import { hashPassword } from '../src/utils/password';
import { logger } from '../src/utils/logger';

const prisma = new PrismaClient();

async function main() {
  logger.info('🌱 Starting database seed...');

  try {
    // Create default permissions
    const permissions = [
      // User permissions
      { name: 'users:create', description: 'Create users', resource: 'users', action: 'create' },
      { name: 'users:read', description: 'Read users', resource: 'users', action: 'read' },
      { name: 'users:update', description: 'Update users', resource: 'users', action: 'update' },
      { name: 'users:delete', description: 'Delete users', resource: 'users', action: 'delete' },
      { name: 'users:approve', description: 'Approve users', resource: 'users', action: 'approve' },

      // Vehicle permissions
      { name: 'vehicles:create', description: 'Create vehicles', resource: 'vehicles', action: 'create' },
      { name: 'vehicles:read', description: 'Read vehicles', resource: 'vehicles', action: 'read' },
      { name: 'vehicles:update', description: 'Update vehicles', resource: 'vehicles', action: 'update' },
      { name: 'vehicles:delete', description: 'Delete vehicles', resource: 'vehicles', action: 'delete' },

      // Violation permissions
      { name: 'violations:create', description: 'Create violations', resource: 'violations', action: 'create' },
      { name: 'violations:read', description: 'Read violations', resource: 'violations', action: 'read' },
      { name: 'violations:update', description: 'Update violations', resource: 'violations', action: 'update' },
      { name: 'violations:delete', description: 'Delete violations', resource: 'violations', action: 'delete' },

      // Plate recognition permissions
      { name: 'plate-recognition:scan', description: 'Perform plate scans', resource: 'plate-recognition', action: 'scan' },
      { name: 'plate-recognition:read', description: 'Read scan history', resource: 'plate-recognition', action: 'read' },

      // Report permissions
      { name: 'reports:create', description: 'Create reports', resource: 'reports', action: 'create' },
      { name: 'reports:read', description: 'Read reports', resource: 'reports', action: 'read' },
      { name: 'reports:delete', description: 'Delete reports', resource: 'reports', action: 'delete' },
      { name: 'reports:export', description: 'Export reports', resource: 'reports', action: 'export' },

      // Analytics permissions
      { name: 'analytics:read', description: 'Read analytics', resource: 'analytics', action: 'read' },

      // System permissions
      { name: 'system:read', description: 'Read system settings', resource: 'system', action: 'read' },
      { name: 'system:update', description: 'Update system settings', resource: 'system', action: 'update' },
      { name: 'system:create', description: 'Create system settings', resource: 'system', action: 'create' },
      { name: 'system:delete', description: 'Delete system settings', resource: 'system', action: 'delete' },
      { name: 'system:maintenance', description: 'System maintenance', resource: 'system', action: 'maintenance' },

      // Audit permissions
      { name: 'audit:read', description: 'Read audit logs', resource: 'audit', action: 'read' },
      { name: 'audit:export', description: 'Export audit logs', resource: 'audit', action: 'export' },
      { name: 'audit:delete', description: 'Delete audit logs', resource: 'audit', action: 'delete' },
    ];

    logger.info('Creating permissions...');
    for (const permission of permissions) {
      await prisma.permission.upsert({
        where: { name: permission.name },
        update: {},
        create: permission,
      });
    }

    // Create default roles
    logger.info('Creating roles...');

    // Administrator role (all permissions)
    const adminRole = await prisma.role.upsert({
      where: { name: 'Administrator' },
      update: {},
      create: {
        name: 'Administrator',
        description: 'Full system access with all permissions',
        isSystem: true,
        permissions: {
          connect: permissions.map(p => ({ name: p.name }))
        }
      },
    });

    // DVLA Officer role
    const dvlaPermissions = permissions.filter(p => 
      p.resource === 'vehicles' || 
      p.resource === 'violations' || 
      p.resource === 'plate-recognition' ||
      (p.resource === 'reports' && p.action !== 'delete') ||
      p.resource === 'analytics' ||
      (p.resource === 'users' && p.action === 'read') ||
      (p.resource === 'audit' && p.action === 'read')
    );

    const dvlaRole = await prisma.role.upsert({
      where: { name: 'DVLA Officer' },
      update: {},
      create: {
        name: 'DVLA Officer',
        description: 'DVLA officer with vehicle and violation management permissions',
        isSystem: true,
        permissions: {
          connect: dvlaPermissions.map(p => ({ name: p.name }))
        }
      },
    });

    // Police Officer role
    const policePermissions = permissions.filter(p => 
      p.resource === 'vehicles' || 
      p.resource === 'violations' || 
      p.resource === 'plate-recognition' ||
      (p.resource === 'reports' && (p.action === 'read' || p.action === 'create')) ||
      p.resource === 'analytics' ||
      (p.resource === 'users' && p.action === 'read') ||
      (p.resource === 'audit' && p.action === 'read')
    );

    const policeRole = await prisma.role.upsert({
      where: { name: 'Police Officer' },
      update: {},
      create: {
        name: 'Police Officer',
        description: 'Police officer with traffic enforcement permissions',
        isSystem: true,
        permissions: {
          connect: policePermissions.map(p => ({ name: p.name }))
        }
      },
    });

    // Create default admin user
    logger.info('Creating default admin user...');
    const hashedPassword = await hashPassword('Admin123!');
    
    const adminUser = await prisma.user.upsert({
      where: { username: 'admin' },
      update: {},
      create: {
        username: 'admin',
        email: 'admin@platerecognition.com',
        hashedPassword,
        firstName: 'System',
        lastName: 'Administrator',
        accountType: 'ADMINISTRATOR',
        status: 'APPROVED',
        isActive: true,
        isEmailVerified: true,
        roleId: adminRole.id,
      },
    });

    // Create sample DVLA user matching frontend credentials
    logger.info('Creating sample DVLA user...');
    const dvlaPassword = await hashPassword('Wattaddo020');
    
    const dvlaUser = await prisma.user.upsert({
      where: { username: '4231220075' },
      update: {},
      create: {
        username: '4231220075',
        email: 'dvla.officer@dvla.gov.uk',
        hashedPassword: dvlaPassword,
        firstName: 'John',
        lastName: 'Officer',
        phoneNumber: '+44 20 7946 0958',
        accountType: 'DVLA',
        status: 'APPROVED',
        isActive: true,
        isEmailVerified: true,
        roleId: dvlaRole.id,
        idNumber: '4231220075',
        position: 'Senior Registration Officer',
        department: 'Vehicle Registration Services',
      },
    });

    // Create sample Police user
    logger.info('Creating sample Police user...');
    const policePassword = await hashPassword('Police123!');
    
    const policeUser = await prisma.user.upsert({
      where: { username: 'police001' },
      update: {},
      create: {
        username: 'police001',
        email: 'officer@police.gov.uk',
        hashedPassword: policePassword,
        firstName: 'Jane',
        lastName: 'Smith',
        phoneNumber: '+44 20 7946 0159',
        accountType: 'POLICE',
        status: 'APPROVED',
        isActive: true,
        isEmailVerified: true,
        roleId: policeRole.id,
        badgeNumber: 'PC001',
        rank: 'Police Constable',
        station: 'Central Traffic Division',
      },
    });

    // Create sample vehicles matching dashboard data
    logger.info('Creating sample vehicles...');
    const sampleVehicles = [
      {
        plateNumber: 'ABC123',
        make: 'Toyota',
        model: 'Camry',
        year: 2020,
        color: 'Blue',
        vin: 'JT2BG12E8X0123456',
        vehicleType: 'CAR' as const,
        registrationDate: new Date('2020-01-15'),
        expiryDate: new Date('2025-01-15'),
        ownerId: dvlaUser.id,
        ownerAddress: '123 King Street',
        ownerCity: 'London',
        ownerState: 'England',
        ownerPostalCode: 'SW1A 1AA',
        ownerCountry: 'UK',
        insuranceNumber: 'INS123456',
        insuranceExpiry: new Date('2024-12-31'),
        insuranceProvider: 'Direct Line',
        motExpiry: new Date('2024-06-15'),
        taxExpiry: new Date('2024-12-31'),
      },
      {
        plateNumber: 'XYZ789',
        make: 'Honda',
        model: 'Civic',
        year: 2019,
        color: 'Red',
        vin: 'JHMFC1F38KX012345',
        vehicleType: 'CAR' as const,
        registrationDate: new Date('2019-03-20'),
        expiryDate: new Date('2024-03-20'),
        ownerId: policeUser.id,
        ownerAddress: '456 Queen Avenue',
        ownerCity: 'Manchester',
        ownerState: 'England',
        ownerPostalCode: 'M1 1AA',
        ownerCountry: 'UK',
        insuranceNumber: 'INS789012',
        insuranceExpiry: new Date('2024-11-30'),
        insuranceProvider: 'Admiral',
        motExpiry: new Date('2024-05-20'),
        taxExpiry: new Date('2024-11-30'),
      },
      // Additional vehicles for dashboard stats
      {
        plateNumber: 'DEF456',
        make: 'Ford',
        model: 'Focus',
        year: 2021,
        color: 'White',
        vehicleType: 'CAR' as const,
        registrationDate: new Date('2021-02-10'),
        expiryDate: new Date('2026-02-10'),
        ownerId: dvlaUser.id,
        ownerAddress: '789 Prince Road',
        ownerCity: 'Birmingham',
        ownerState: 'England',
        ownerPostalCode: 'B1 1AA',
        ownerCountry: 'UK',
      },
    ];

    for (const vehicle of sampleVehicles) {
      await prisma.vehicle.upsert({
        where: { plateNumber: vehicle.plateNumber },
        update: {},
        create: vehicle,
      });
    }

    // Create sample violations matching dashboard data
    logger.info('Creating sample violations...');
    const sampleViolations = [
      {
        plateNumber: 'ABC123',
        violationType: 'SPEEDING' as const,
        description: 'Exceeded speed limit by 15 mph on M25 motorway',
        location: 'M25 Motorway, Junction 15',
        coordinates: '51.5074,-0.1278',
        fineAmount: 150.00,
        violationDate: new Date('2024-01-15T14:30:00Z'),
        dueDate: new Date('2024-02-15T23:59:59Z'),
        status: 'PENDING' as const,
        issuedById: policeUser.id,
        images: ['/uploads/violations/abc123_speed_001.jpg'],
        evidenceNotes: 'Speed camera detection on motorway',
      },
      {
        plateNumber: 'XYZ789',
        violationType: 'PARKING' as const,
        description: 'Parking in disabled bay without valid permit',
        location: 'High Street Car Park, Manchester',
        coordinates: '53.4808,-2.2426',
        fineAmount: 50.00,
        violationDate: new Date('2024-01-20T10:15:00Z'),
        dueDate: new Date('2024-02-20T23:59:59Z'),
        status: 'CONFIRMED' as const,
        issuedById: policeUser.id,
        images: ['/uploads/violations/xyz789_parking_001.jpg'],
        evidenceNotes: 'Traffic warden observation and photographic evidence',
      },
      {
        plateNumber: 'DEF456',
        violationType: 'RED_LIGHT' as const,
        description: 'Proceeded through red traffic light',
        location: 'Oxford Street Junction, London',
        coordinates: '51.5156,-0.1414',
        fineAmount: 200.00,
        violationDate: new Date('2024-01-22T16:45:00Z'),
        dueDate: new Date('2024-02-22T23:59:59Z'),
        status: 'RESOLVED' as const,
        issuedById: policeUser.id,
        paidAmount: 200.00,
        paidAt: new Date('2024-01-25T09:30:00Z'),
        paymentMethod: 'Credit Card',
        receiptNumber: 'RCP001234',
      },
    ];

    for (const violation of sampleViolations) {
      await prisma.violation.create({
        data: violation,
      });
    }

    // Create sample vehicle scans
    logger.info('Creating sample vehicle scans...');
    const sampleScans = [
      {
        plateNumber: 'ABC123',
        location: 'M25 Motorway Camera 15A',
        coordinates: '51.5074,-0.1278',
        confidence: 0.95,
        imageUrl: '/uploads/scans/scan_001.jpg',
        cameraId: 'CAM_M25_15A',
        scannerType: 'fixed',
        isViolation: true,
        violationTypes: ['SPEEDING'],
        imageQuality: 'excellent',
        weatherConditions: 'clear',
        timeOfDay: 'day',
        scanDateTime: new Date('2024-01-15T14:30:00Z'),
      },
      {
        plateNumber: 'XYZ789',
        location: 'High Street Car Park',
        coordinates: '53.4808,-2.2426',
        confidence: 0.88,
        imageUrl: '/uploads/scans/scan_002.jpg',
        scannerType: 'handheld',
        isViolation: true,
        violationTypes: ['PARKING'],
        imageQuality: 'good',
        weatherConditions: 'clear',
        timeOfDay: 'day',
        scanDateTime: new Date('2024-01-20T10:15:00Z'),
      },
    ];

    for (const scan of sampleScans) {
      await prisma.vehicleScan.create({
        data: scan,
      });
    }

    // Create system settings
    logger.info('Creating system settings...');
    const systemSettings = [
      {
        key: 'system.name',
        value: 'Plate Recognition System',
        description: 'System name displayed in UI',
        category: 'general',
        isPublic: true,
      },
      {
        key: 'system.version',
        value: '1.0.0',
        description: 'Current system version',
        category: 'general',
        isPublic: true,
      },
      {
        key: 'notifications.email.enabled',
        value: 'true',
        description: 'Enable email notifications',
        category: 'notifications',
        isPublic: false,
      },
      {
        key: 'security.session.timeout',
        value: '30',
        description: 'Session timeout in minutes',
        category: 'security',
        isPublic: false,
      },
      {
        key: 'security.password.min_length',
        value: '8',
        description: 'Minimum password length',
        category: 'security',
        isPublic: false,
      },
      {
        key: 'ocr.confidence.threshold',
        value: '0.8',
        description: 'Minimum OCR confidence threshold',
        category: 'ocr',
        isPublic: false,
      },
      {
        key: 'violations.fine.speeding.default',
        value: '150',
        description: 'Default fine amount for speeding violations',
        category: 'violations',
        isPublic: false,
      },
      {
        key: 'violations.fine.parking.default',
        value: '50',
        description: 'Default fine amount for parking violations',
        category: 'violations',
        isPublic: false,
      },
    ];

    for (const setting of systemSettings) {
      await prisma.systemSetting.upsert({
        where: { key: setting.key },
        update: {},
        create: setting,
      });
    }

    // Create sample notifications
    logger.info('Creating sample notifications...');
    const notifications = [
      {
        userId: adminUser.id,
        type: 'SYSTEM_ALERT' as const,
        title: 'System Startup',
        message: 'Plate Recognition System has been successfully initialized',
        isRead: false,
      },
      {
        userId: dvlaUser.id,
        type: 'VIOLATION_CREATED' as const,
        title: 'New Violation Detected',
        message: 'Vehicle ABC123 has a new speeding violation',
        isRead: false,
      },
    ];

    for (const notification of notifications) {
      await prisma.notification.create({
        data: notification,
      });
    }

    logger.info('✅ Database seed completed successfully!');
    logger.info('\n📋 Default Users Created:');
    logger.info('👑 Admin: username=admin, password=Admin123!');
    logger.info('👤 DVLA Officer: username=4231220075, password=Wattaddo020');
    logger.info('👤 Police Officer: username=police001, password=Police123!');
    logger.info('\n📊 Sample Data:');
    logger.info(`• ${sampleVehicles.length} vehicles registered`);
    logger.info(`• ${sampleViolations.length} violations recorded`);
    logger.info(`• ${sampleScans.length} plate scans logged`);
    logger.info(`• ${systemSettings.length} system settings configured`);

  } catch (error) {
    logger.error('❌ Seed failed:', error);
    throw error;
  }
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
