import nodemailer from 'nodemailer';
import { logger } from '../utils/logger';
import { EmailOptions } from '../types';

class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransporter({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT || '587'),
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  async sendEmail(options: EmailOptions): Promise<void> {
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: options.to,
        subject: options.subject,
        html: this.renderTemplate(options.template, options.data),
      };

      await this.transporter.sendMail(mailOptions);
      logger.info(`Email sent successfully to ${options.to}`);
    } catch (error) {
      logger.error('Failed to send email:', error);
      throw new Error('Email sending failed');
    }
  }

  async sendNewUserRegistrationNotification(data: {
    user: any;
    adminEmails: string[];
  }): Promise<void> {
    const { user, adminEmails } = data;

    for (const adminEmail of adminEmails) {
      await this.sendEmail({
        to: adminEmail,
        subject: 'New User Registration - Pending Approval',
        template: 'newUserRegistration',
        data: {
          userName: `${user.firstName} ${user.lastName}`,
          userEmail: user.email,
          accountType: user.accountType,
          username: user.username,
          approvalUrl: `${process.env.FRONTEND_URL}/admin/user-approvals`,
        },
      });
    }
  }

  async sendUserApprovalNotification(data: {
    user: any;
    approved: boolean;
    reason?: string;
  }): Promise<void> {
    const { user, approved, reason } = data;

    await this.sendEmail({
      to: user.email,
      subject: approved ? 'Account Approved' : 'Account Rejected',
      template: approved ? 'userApproved' : 'userRejected',
      data: {
        firstName: user.firstName,
        lastName: user.lastName,
        reason: reason,
        loginUrl: `${process.env.FRONTEND_URL}/login`,
      },
    });
  }

  async sendPasswordResetEmail(data: {
    email: string;
    firstName: string;
    resetToken: string;
    resetUrl: string;
  }): Promise<void> {
    const { email, firstName, resetToken, resetUrl } = data;

    await this.sendEmail({
      to: email,
      subject: 'Password Reset Request',
      template: 'passwordReset',
      data: {
        firstName,
        resetUrl,
        resetToken,
        expiryTime: '1 hour',
      },
    });
  }

  async sendViolationNotification(data: {
    violation: any;
    vehicle: any;
    owner: any;
  }): Promise<void> {
    const { violation, vehicle, owner } = data;

    await this.sendEmail({
      to: owner.email,
      subject: 'Traffic Violation Notice',
      template: 'violationNotification',
      data: {
        ownerName: `${owner.firstName} ${owner.lastName}`,
        plateNumber: vehicle.plateNumber,
        violationType: violation.violationType,
        location: violation.location,
        violationDate: violation.violationDate,
        fineAmount: violation.fineAmount,
        dueDate: violation.dueDate,
        paymentUrl: `${process.env.FRONTEND_URL}/payment/${violation.id}`,
      },
    });
  }

  async sendSystemAlert(data: {
    recipients: string[];
    subject: string;
    message: string;
    priority: 'low' | 'medium' | 'high' | 'critical';
  }): Promise<void> {
    const { recipients, subject, message, priority } = data;

    for (const recipient of recipients) {
      await this.sendEmail({
        to: recipient,
        subject: `[${priority.toUpperCase()}] ${subject}`,
        template: 'systemAlert',
        data: {
          message,
          priority,
          timestamp: new Date().toISOString(),
        },
      });
    }
  }

  private renderTemplate(templateName: string, data: Record<string, any>): string {
    // In a production environment, you would use a proper template engine
    // like Handlebars, Mustache, or EJS. For this example, we'll use simple templates.
    
    const templates: Record<string, string> = {
      newUserRegistration: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">New User Registration</h2>
          <p>A new user has registered and is pending approval:</p>
          <ul>
            <li><strong>Name:</strong> {{userName}}</li>
            <li><strong>Email:</strong> {{userEmail}}</li>
            <li><strong>Username:</strong> {{username}}</li>
            <li><strong>Account Type:</strong> {{accountType}}</li>
          </ul>
          <p>
            <a href="{{approvalUrl}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              Review and Approve
            </a>
          </p>
        </div>
      `,
      
      userApproved: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #28a745;">Account Approved</h2>
          <p>Dear {{firstName}} {{lastName}},</p>
          <p>Your account has been approved! You can now log in to the Plate Recognition System.</p>
          <p>
            <a href="{{loginUrl}}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              Login Now
            </a>
          </p>
        </div>
      `,
      
      userRejected: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #dc3545;">Account Rejected</h2>
          <p>Dear {{firstName}} {{lastName}},</p>
          <p>Unfortunately, your account registration has been rejected.</p>
          {{#if reason}}<p><strong>Reason:</strong> {{reason}}</p>{{/if}}
          <p>If you believe this is an error, please contact support.</p>
        </div>
      `,
      
      passwordReset: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>Dear {{firstName}},</p>
          <p>You have requested to reset your password. Click the link below to reset it:</p>
          <p>
            <a href="{{resetUrl}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              Reset Password
            </a>
          </p>
          <p>This link will expire in {{expiryTime}}.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `,
      
      violationNotification: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #dc3545;">Traffic Violation Notice</h2>
          <p>Dear {{ownerName}},</p>
          <p>A traffic violation has been recorded for your vehicle:</p>
          <ul>
            <li><strong>Plate Number:</strong> {{plateNumber}}</li>
            <li><strong>Violation Type:</strong> {{violationType}}</li>
            <li><strong>Location:</strong> {{location}}</li>
            <li><strong>Date:</strong> {{violationDate}}</li>
            <li><strong>Fine Amount:</strong> ${{fineAmount}}</li>
            <li><strong>Due Date:</strong> {{dueDate}}</li>
          </ul>
          <p>
            <a href="{{paymentUrl}}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              Pay Fine
            </a>
          </p>
        </div>
      `,
      
      systemAlert: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: {{#eq priority 'critical'}}#dc3545{{else}}{{#eq priority 'high'}}#fd7e14{{else}}#007bff{{/eq}}{{/eq}};">System Alert</h2>
          <p><strong>Priority:</strong> {{priority}}</p>
          <p><strong>Timestamp:</strong> {{timestamp}}</p>
          <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
            {{message}}
          </div>
        </div>
      `,
    };

    let template = templates[templateName] || '<p>{{message}}</p>';

    // Simple template replacement (in production, use a proper template engine)
    Object.keys(data).forEach(key => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      template = template.replace(regex, data[key] || '');
    });

    return template;
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      logger.info('Email service connection verified');
      return true;
    } catch (error) {
      logger.error('Email service connection failed:', error);
      return false;
    }
  }
}

export const emailService = new EmailService();
