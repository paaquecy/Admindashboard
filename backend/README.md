# Plate Recognition System - Backend API

A comprehensive backend API for the Plate Recognition and Traffic Violation Management System built with Node.js, Express, TypeScript, Prisma, and PostgreSQL.

## 🚀 Features

### Core Functionality
- **🔐 Authentication & Authorization**: JWT-based auth with role-based permissions (RBAC)
- **👥 User Management**: Multi-role user system (Admin, DVLA Officers, Police Officers)
- **🚗 Vehicle Registry**: Complete vehicle registration and management system
- **⚖️ Violation Management**: Traffic violation tracking, processing, and payment handling
- **📷 Plate Recognition**: OCR-based license plate detection with confidence scoring
- **📊 Analytics & Reporting**: Comprehensive reporting with data export capabilities
- **📝 Audit Logging**: Complete system activity tracking with risk assessment
- **📧 Email Notifications**: Automated email alerts and notifications
- **🔔 Real-time Notifications**: In-app notification system

### Security Features
- **🛡️ Two-Factor Authentication**: TOTP-based 2FA with QR code setup
- **🔒 Session Management**: Secure session handling with Redis caching
- **⚡ Rate Limiting**: Protection against brute force attacks
- **🔍 Input Validation**: Comprehensive request validation
- **🏷️ SQL Injection Protection**: Prisma ORM with prepared statements
- **🌐 CORS Protection**: Configurable cross-origin resource sharing
- **🔐 Password Security**: bcrypt hashing with configurable rounds

### Performance & Monitoring
- **⚡ Redis Caching**: High-performance caching layer
- **📈 Health Monitoring**: System health checks and monitoring
- **📊 Performance Metrics**: Response time tracking and analytics
- **🗄️ Database Optimization**: Efficient queries with Prisma
- **📦 File Processing**: Image upload and processing with Sharp

## 🛠 Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express.js with TypeScript
- **Database**: PostgreSQL 14+ with Prisma ORM
- **Cache**: Redis for sessions and performance
- **Authentication**: JWT with refresh tokens
- **File Processing**: Sharp for image processing
- **Email**: Nodemailer with template support
- **Validation**: express-validator
- **Logging**: Winston with log rotation
- **Security**: Helmet, CORS, Rate limiting
- **Testing**: Jest (ready for tests)

## 📋 Prerequisites

- Node.js 18 or higher
- PostgreSQL 14 or higher
- Redis 6 or higher
- npm or yarn package manager

## 🔧 Installation & Setup

### 1. Clone and Install Dependencies

```bash
cd backend
npm install
```

### 2. Environment Configuration

Create a `.env` file in the backend directory:

```bash
cp .env.example .env
```

Update the `.env` file with your configuration:

```env
# Database (Required)
DATABASE_URL="postgresql://username:password@localhost:5432/plate_recognition_db"

# JWT (Required)
JWT_SECRET=your-super-secret-jwt-key-here-at-least-32-characters
REFRESH_TOKEN_SECRET=your-refresh-token-secret-here

# Redis (Optional for development)
REDIS_URL=redis://localhost:6379

# Email (Optional for development)
EMAIL_HOST=smtp.gmail.com
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Frontend URL
FRONTEND_URL=http://localhost:5173
CORS_ORIGIN=http://localhost:5173
```

### 3. Database Setup

```bash
# Generate Prisma client
npm run db:generate

# Run database migrations
npm run db:migrate

# Seed the database with initial data
npm run db:seed
```

### 4. Start the Server

```bash
# Development mode with hot reload
npm run dev

# Production mode
npm run build
npm start
```

The API will be available at `http://localhost:3001`

## 👥 Default Users

After seeding the database, you can login with these default accounts:

| Role | Username | Password | Description |
|------|----------|----------|-------------|
| **Administrator** | `admin` | `Admin123!` | Full system access |
| **DVLA Officer** | `4231220075` | `Wattaddo020` | Vehicle registration management |
| **Police Officer** | `police001` | `Police123!` | Traffic violation management |

> **Note**: The DVLA Officer credentials match the frontend mock data for seamless integration.

## 📚 API Documentation

### Base URL
```
http://localhost:3001/api
```

### Authentication
Most endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

### Core Endpoints

#### 🔐 Authentication
```http
POST /api/auth/login          # User login
POST /api/auth/register       # User registration  
POST /api/auth/logout         # User logout
POST /api/auth/refresh        # Refresh access token
GET  /api/auth/profile        # Get current user profile
POST /api/auth/change-password # Change password
POST /api/auth/two-factor     # Setup/disable 2FA
```

#### 👥 User Management
```http
GET    /api/users             # List all users (paginated)
GET    /api/users/pending     # Get pending user approvals
POST   /api/users             # Create new user (admin only)
GET    /api/users/:id         # Get user by ID
PUT    /api/users/:id         # Update user
DELETE /api/users/:id         # Delete user
POST   /api/users/:id/approval # Approve/reject user
```

#### 🚗 Vehicle Management
```http
GET    /api/vehicles          # List vehicles (paginated, searchable)
GET    /api/vehicles/search   # Search vehicles by plate
POST   /api/vehicles          # Register new vehicle
GET    /api/vehicles/:id      # Get vehicle by ID
PUT    /api/vehicles/:id      # Update vehicle information
DELETE /api/vehicles/:id      # Delete vehicle
GET    /api/vehicles/:id/violations # Get vehicle violations
```

#### ⚖️ Violation Management
```http
GET    /api/violations        # List violations (filtered, paginated)
POST   /api/violations        # Create new violation
GET    /api/violations/:id    # Get violation by ID
PUT    /api/violations/:id    # Update violation
DELETE /api/violations/:id    # Delete violation
PATCH  /api/violations/:id/status # Update violation status
POST   /api/violations/:id/payment # Process payment
```

#### 📷 Plate Recognition
```http
POST   /api/plate-recognition/scan        # Scan image for plates
POST   /api/plate-recognition/scan-base64 # Scan base64 image
GET    /api/plate-recognition/scans       # Get scan history
POST   /api/plate-recognition/batch-scan  # Batch scan multiple images
GET    /api/plate-recognition/stats       # Get recognition statistics
```

#### 📊 Analytics & Reports
```http
GET    /api/analytics/dashboard           # Dashboard analytics
GET    /api/analytics/violations/trends   # Violation trends
POST   /api/reports                       # Generate report
GET    /api/reports/:id/download          # Download report
POST   /api/reports/export/csv            # Export data to CSV
```

#### ⚙️ System Management
```http
GET    /api/system/health                 # Health check
GET    /api/system/settings               # System settings
PUT    /api/system/settings/:key          # Update setting
POST   /api/system/maintenance/cleanup    # Database cleanup
```

### Response Format

All API responses follow this structure:

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { ... },
  "meta": {
    "total": 100,
    "page": 1,
    "limit": 10,
    "totalPages": 10
  }
}
```

Error responses:
```json
{
  "success": false,
  "message": "Error description",
  "errors": [...]
}
```

## 🔐 Security Features

### Authentication & Authorization
- **JWT Tokens**: Secure access and refresh token implementation
- **Role-Based Access Control**: Granular permissions system
- **Two-Factor Authentication**: TOTP-based 2FA with backup codes
- **Session Management**: Concurrent session limits and tracking

### Security Hardening
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: Prisma ORM with prepared statements
- **XSS Protection**: Helmet security headers
- **CORS Configuration**: Configurable cross-origin policies

### Audit & Monitoring
- **Comprehensive Audit Logs**: All actions tracked with risk assessment
- **Failed Login Tracking**: Account lockout after failed attempts
- **Suspicious Activity Detection**: Automated risk assessment
- **IP Address Tracking**: Location and device information

## 📊 Database Schema

The system uses PostgreSQL with comprehensive models:

### Core Entities
- **Users**: System users with roles and detailed profiles
- **Roles & Permissions**: Flexible RBAC system
- **Vehicles**: Complete vehicle registry with owner information
- **Violations**: Traffic violations with payment tracking
- **VehicleScans**: Plate recognition scan history with confidence scores

### Supporting Entities
- **Reports**: Generated reports with parameters and files
- **AuditLogs**: Complete system activity tracking
- **SystemSettings**: Configurable system parameters
- **Notifications**: In-app notification system
- **UserSessions**: Secure session management

## 🔄 Development Workflow

### Running in Development
```bash
# Start with hot reload
npm run dev

# View database in Prisma Studio
npm run db:studio

# Run database migrations
npm run db:migrate

# Reset database (careful!)
npm run db:reset
```

### Code Quality
```bash
# Linting
npm run lint

# Type checking
npx tsc --noEmit
```

### Database Operations
```bash
# Generate Prisma client after schema changes
npm run db:generate

# Create and apply new migration
npx prisma migrate dev --name migration_name

# Reset database and re-seed
npm run db:reset
```

## 📁 Project Structure

```
backend/
├── prisma/
│   ├── schema.prisma         # Database schema
│   └── seed.ts              # Database seed data
├── src/
│   ├── controllers/         # Request handlers
│   │   ├── authController.ts
│   │   ├── userController.ts
│   │   └── ...
│   ├── middlewares/         # Express middlewares
│   │   ├── auth.ts
│   │   ├── errorHandler.ts
│   │   └── validation.ts
│   ├── routes/             # API route definitions
│   │   ├── auth.ts
│   │   ├── users.ts
│   │   └── ...
│   ├── services/           # Business logic services
│   │   ├── auditLogService.ts
│   │   ├── emailService.ts
│   │   └── ...
│   ├── types/              # TypeScript type definitions
│   ├── utils/              # Utility functions
│   │   ├── database.ts
│   │   ├── redis.ts
│   │   ├── logger.ts
│   │   └── ...
│   └── server.ts           # Application entry point
├── uploads/                # File upload directory
├── logs/                  # Application logs
├── .env.example           # Environment template
└── package.json
```

## 🚀 Frontend Integration

### API Integration Points
1. **Authentication Flow**: Login returns JWT token for subsequent requests
2. **Real-time Updates**: Built-in notification system for live updates
3. **File Uploads**: Multipart form data support for image uploads
4. **Pagination**: Consistent pagination across all list endpoints
5. **Error Handling**: Standardized error responses with detailed messages

### Dashboard Data
The backend provides all data needed for the frontend dashboard:
- **KPI Metrics**: Vehicle counts, violation statistics, growth metrics
- **Recent Activities**: Real-time activity feed with timestamps
- **Pending Items**: User approvals and upcoming deadlines
- **Analytics**: Trend data and performance metrics

## 🐳 Docker Support

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3001
CMD ["npm", "start"]
```

## 📞 Support & Troubleshooting

### Common Issues

1. **Database Connection Issues**
   - Check PostgreSQL is running: `sudo service postgresql status`
   - Verify DATABASE_URL in .env file
   - Check database exists and permissions

2. **Redis Connection Issues**
   - Check Redis is running: `redis-cli ping`
   - Verify REDIS_URL in .env file
   - Redis is optional for development

3. **Email Issues**
   - Email service is optional for development
   - Check EMAIL_HOST, EMAIL_USER, EMAIL_PASS settings
   - Use app passwords for Gmail

### Health Checks
- API Health: `GET /health`
- Database: Check Prisma Studio at `npm run db:studio`
- Redis: Use `redis-cli` to test connection

### Logs
- Application logs: `logs/combined.log`
- Error logs: `logs/error.log`
- Console output in development mode

## 📄 License

This project is proprietary software for the Plate Recognition System.

---

## 🎯 Next Steps for Frontend Integration

1. **Update Frontend API Calls**: Point all API calls to `http://localhost:3001/api`
2. **Authentication Integration**: Use the JWT tokens from login response
3. **Error Handling**: Implement proper error handling for API responses
4. **Real-time Updates**: Consider implementing WebSocket for live notifications
5. **File Upload**: Integrate image upload for plate recognition features

The backend is now fully functional and ready to support all frontend features! 🚀
