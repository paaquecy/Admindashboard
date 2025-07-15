import React, { useState } from 'react';
import { ArrowLeft, User, Shield, Car, Phone, Mail, Lock, CheckCircle, XCircle, Eye, EyeOff } from 'lucide-react';

interface RegisterPageProps {
  onBackToLogin: () => void;
  onRegisterSuccess: () => void;
  onNewRegistration: (registrationData: any) => void;
}

interface FormData {
  firstName: string;
  lastName: string;
  badgeNumber: string;
  rank: string;
  station: string;
  idNumber: string;
  position: string;
  telephone: string;
  email: string;
  password: string;
  confirmPassword: string;
}

interface PasswordRequirement {
  id: string;
  text: string;
  met: boolean;
}

const RegisterPage: React.FC<RegisterPageProps> = ({ onBackToLogin, onRegisterSuccess, onNewRegistration }) => {
  const [selectedAccountType, setSelectedAccountType] = useState<'police' | 'dvla'>('police');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [formData, setFormData] = useState<FormData>({
    firstName: '',
    lastName: '',
    badgeNumber: '',
    rank: '',
    station: '',
    idNumber: '',
    position: '',
    telephone: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  const passwordRequirements: PasswordRequirement[] = [
    {
      id: 'length',
      text: 'Minimum 8 characters',
      met: formData.password.length >= 8
    },
    {
      id: 'uppercase',
      text: 'At least one uppercase letter',
      met: /[A-Z]/.test(formData.password)
    },
    {
      id: 'lowercase',
      text: 'At least one lowercase letter',
      met: /[a-z]/.test(formData.password)
    },
    {
      id: 'number',
      text: 'At least one number',
      met: /\d/.test(formData.password)
    },
    {
      id: 'special',
      text: 'At least one special character',
      met: /[!@#$%^&*(),.?":{}|<>]/.test(formData.password)
    }
  ];

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    console.log(`${name} changed to:`, value);
  };

  const handleAccountTypeSelect = (type: 'police' | 'dvla') => {
    setSelectedAccountType(type);
    console.log('Account type selected:', type);
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
    console.log('Password visibility toggled to:', !showPassword);
  };

  const toggleConfirmPasswordVisibility = () => {
    setShowConfirmPassword(!showConfirmPassword);
    console.log('Confirm password visibility toggled to:', !showConfirmPassword);
  };

  const validateForm = (): boolean => {
    // Check if all required fields are filled
    const requiredFields = ['firstName', 'lastName', 'telephone', 'email', 'password', 'confirmPassword'];
    
    // Add conditional required fields for police officers
    if (selectedAccountType === 'police') {
      requiredFields.push('badgeNumber', 'rank', 'station');
    }
    
    // Add conditional required fields for DVLA officers
    if (selectedAccountType === 'dvla') {
      requiredFields.push('idNumber', 'position');
    }

    for (const field of requiredFields) {
      if (!formData[field as keyof FormData].trim()) {
        alert(`Please fill in the ${field.replace(/([A-Z])/g, ' $1').toLowerCase()}`);
        return false;
      }
    }

    // Check password requirements
    const unmetRequirements = passwordRequirements.filter(req => !req.met);
    if (unmetRequirements.length > 0) {
      alert('Password does not meet all requirements');
      return false;
    }

    // Check password confirmation
    if (formData.password !== formData.confirmPassword) {
      alert('Passwords do not match');
      return false;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      alert('Please enter a valid email address');
      return false;
    }

    // Validate phone format
    const phoneRegex = /^\+?[\d\s\-\(\)]+$/;
    if (!phoneRegex.test(formData.telephone)) {
      alert('Please enter a valid telephone number');
      return false;
    }

    return true;
  };

  const handleCreateAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log('Create Account button clicked');

    // Basic validation - check if required fields are filled
    const requiredFields = ['firstName', 'lastName', 'telephone', 'email', 'password', 'confirmPassword'];
    
    // Add conditional required fields
    if (selectedAccountType === 'police') {
      requiredFields.push('badgeNumber', 'rank', 'station');
    } else if (selectedAccountType === 'dvla') {
      requiredFields.push('idNumber', 'position');
    }

    // Check if all required fields are filled
    for (const field of requiredFields) {
      if (!formData[field as keyof FormData]?.trim()) {
        alert(`Please fill in the ${field.replace(/([A-Z])/g, ' $1').toLowerCase()}`);
        return;
      }
    }

    // Check password requirements
    const unmetRequirements = passwordRequirements.filter(req => !req.met);
    if (unmetRequirements.length > 0) {
      alert('Password does not meet all requirements');
      return;
    }

    // Check password confirmation
    if (formData.password !== formData.confirmPassword) {
      alert('Passwords do not match');
      return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      alert('Please enter a valid email address');
      return;
    }

    setIsSubmitting(true);

    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const registrationData = {
        accountType: selectedAccountType,
        ...formData,
        password: '[REDACTED]',
        confirmPassword: '[REDACTED]'
      };
      
      console.log('Account creation successful:', registrationData);
      
      // Add to pending approvals
      onNewRegistration({
        accountType: selectedAccountType,
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        telephone: formData.telephone,
        ...(selectedAccountType === 'police' 
          ? {
              badgeNumber: formData.badgeNumber,
              rank: formData.rank,
              station: formData.station
            }
          : {
              idNumber: formData.idNumber,
              position: formData.position
            }
        )
      });

      alert('Account created successfully! Your account is pending admin approval. You will be notified once approved and can then login.');
      onRegisterSuccess();
    } catch (error) {
      console.error('Account creation failed:', error);
      alert('Account creation failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBackToLogin = () => {
    console.log('Back to Login button clicked');
    onBackToLogin();
  };

  const allPasswordRequirementsMet = passwordRequirements.every(req => req.met);
  const passwordsMatch = formData.password && formData.confirmPassword && formData.password === formData.confirmPassword;
  const passwordsDontMatch = formData.password && formData.confirmPassword && formData.password !== formData.confirmPassword;

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4 font-['Inter']">
      <div className="w-full max-w-2xl">
        {/* Back to Login Button */}
        <button
          onClick={handleBackToLogin}
          className="mb-6 flex items-center text-blue-600 hover:text-blue-800 transition-colors"
        >
          <ArrowLeft size={20} className="mr-2" />
          Back to Login
        </button>

        {/* Main Registration Card */}
        <div className="bg-white rounded-lg shadow-lg p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              Create Your Account
            </h1>
          </div>

          {/* Account Type Selection */}
          <div className="mb-8">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Police Officer Card */}
              <div
                onClick={() => handleAccountTypeSelect('police')}
                className={`p-6 rounded-lg border-2 cursor-pointer transition-all hover:shadow-md ${
                  selectedAccountType === 'police'
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 bg-white hover:border-gray-300'
                }`}
              >
                <div className="flex flex-col items-center text-center">
                  <Shield className={`w-12 h-12 mb-3 ${
                    selectedAccountType === 'police' ? 'text-blue-600' : 'text-gray-400'
                  }`} />
                  <h3 className={`text-lg font-semibold mb-2 ${
                    selectedAccountType === 'police' ? 'text-blue-900' : 'text-gray-900'
                  }`}>
                    Police Officer
                  </h3>
                  <p className={`text-sm ${
                    selectedAccountType === 'police' ? 'text-blue-700' : 'text-gray-600'
                  }`}>
                    Law enforcement personnel with vehicle scanning and violation flagging capabilities
                  </p>
                </div>
              </div>

              {/* DVLA Officer Card */}
              <div
                onClick={() => handleAccountTypeSelect('dvla')}
                className={`p-6 rounded-lg border-2 cursor-pointer transition-all hover:shadow-md ${
                  selectedAccountType === 'dvla'
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 bg-white hover:border-gray-300'
                }`}
              >
                <div className="flex flex-col items-center text-center">
                  <Car className={`w-12 h-12 mb-3 ${
                    selectedAccountType === 'dvla' ? 'text-blue-600' : 'text-gray-400'
                  }`} />
                  <h3 className={`text-lg font-semibold mb-2 ${
                    selectedAccountType === 'dvla' ? 'text-blue-900' : 'text-gray-900'
                  }`}>
                    DVLA Officer
                  </h3>
                  <p className={`text-sm ${
                    selectedAccountType === 'dvla' ? 'text-blue-700' : 'text-gray-600'
                  }`}>
                    Vehicle registration authority with data entry and analysis access
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Registration Form */}
          <form onSubmit={handleCreateAccount} className="space-y-8">
            {/* Personal Information Section */}
            <div>
              <div className="flex items-center mb-4">
                <User className="w-5 h-5 mr-2 text-gray-500" />
                <h3 className="text-lg font-semibold text-gray-900">Personal Information</h3>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    First Name
                  </label>
                  <input
                    type="text"
                    name="firstName"
                    value={formData.firstName}
                    onChange={handleInputChange}
                    placeholder="Enter your first name"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                    required
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Last Name
                  </label>
                  <input
                    type="text"
                    name="lastName"
                    value={formData.lastName}
                    onChange={handleInputChange}
                    placeholder="Enter your last name"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                    required
                  />
                </div>
              </div>
            </div>

            {/* Police Officer Details Section (Conditional) */}
            {selectedAccountType === 'police' && (
              <div>
                <div className="flex items-center mb-4">
                  <Shield className="w-5 h-5 mr-2 text-gray-500" />
                  <h3 className="text-lg font-semibold text-gray-900">Police Officer Details</h3>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Badge Number
                    </label>
                    <input
                      type="text"
                      name="badgeNumber"
                      value={formData.badgeNumber}
                      onChange={handleInputChange}
                      placeholder="Enter your badge number"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                      required
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Rank
                    </label>
                    <input
                      type="text"
                      name="rank"
                      value={formData.rank}
                      onChange={handleInputChange}
                      placeholder="e.g., Sergeant, Inspector"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                      required
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Station
                    </label>
                    <input
                      type="text"
                      name="station"
                      value={formData.station}
                      onChange={handleInputChange}
                      placeholder="e.g., Central Station"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                      required
                    />
                  </div>
                </div>
              </div>
            )}

            {/* DVLA Officer Details Section (Conditional) */}
            {selectedAccountType === 'dvla' && (
              <div>
                <div className="flex items-center mb-4">
                  <Car className="w-5 h-5 mr-2 text-gray-500" />
                  <h3 className="text-lg font-semibold text-gray-900">DVLA Officer Details</h3>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      ID Number
                    </label>
                    <input
                      type="text"
                      name="idNumber"
                      value={formData.idNumber}
                      onChange={handleInputChange}
                      placeholder="Enter your DVLA ID number"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                      required
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Position in DVLA
                    </label>
                    <input
                      type="text"
                      name="position"
                      value={formData.position}
                      onChange={handleInputChange}
                      placeholder="e.g., Registration Officer, Inspector"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                      required
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Contact Information Section */}
            <div>
              <div className="flex items-center mb-4">
                <Phone className="w-5 h-5 mr-2 text-gray-500" />
                <h3 className="text-lg font-semibold text-gray-900">Contact Information</h3>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Telephone
                  </label>
                  <input
                    type="tel"
                    name="telephone"
                    value={formData.telephone}
                    onChange={handleInputChange}
                    placeholder="e.g., +233 123 456 789"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                    required
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Professional Email
                  </label>
                  <div className="relative">
                    <Mail className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleInputChange}
                      placeholder={selectedAccountType === 'police' ? 'e.g., your.name@police.uk' : 'e.g., your.name@dvla.gov'}
                      placeholder={selectedAccountType === 'police' ? 'e.g., your.name@police.uk' : 'e.g., your.name@dvla.gov.uk'}
                      className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                      required
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Security Section */}
            <div>
              <div className="flex items-center mb-4">
                <Lock className="w-5 h-5 mr-2 text-gray-500" />
                <h3 className="text-lg font-semibold text-gray-900">Security</h3>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <Lock className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      name="password"
                      value={formData.password}
                      onChange={handleInputChange}
                      placeholder="Enter your password"
                      className="w-full pl-10 pr-12 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                      required
                    />
                    <button
                      type="button"
                      onClick={togglePasswordVisibility}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors"
                    >
                      {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                    </button>
                  </div>
                  
                  {/* Password Requirements */}
                  <div className="mt-3 space-y-1">
                    {passwordRequirements.map((requirement) => (
                      <div key={requirement.id} className={`flex items-center text-sm ${
                        requirement.met ? 'text-green-600' : 'text-red-600'
                      }`}>
                        {requirement.met ? (
                          <CheckCircle size={14} className="mr-2 flex-shrink-0" />
                        ) : (
                          <XCircle size={14} className="mr-2 flex-shrink-0" />
                        )}
                        <span>{requirement.text}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <Lock className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      placeholder="Confirm your password"
                      className={`w-full pl-10 pr-12 py-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors ${
                        passwordsDontMatch 
                          ? 'border-red-300 bg-red-50' 
                          : 'border-gray-300'
                      }`}
                      required
                    />
                    <button
                      type="button"
                      onClick={toggleConfirmPasswordVisibility}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors"
                    >
                      {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                    </button>
                  </div>
                  
                  {/* Password Match Validation */}
                  {passwordsDontMatch && (
                    <div className="mt-2 flex items-center text-sm text-red-600">
                      <XCircle size={14} className="mr-2 flex-shrink-0" />
                      <span>Passwords do not match</span>
                    </div>
                  )}
                  
                  {passwordsMatch && (
                    <div className="mt-2 flex items-center text-sm text-green-600">
                      <CheckCircle size={14} className="mr-2 flex-shrink-0" />
                      <span>Passwords match</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Create Account Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className={`w-full py-4 px-6 rounded-lg font-semibold text-lg transition-colors ${
                isSubmitting
                  ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {isSubmitting ? (
                <div className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white mr-3"></div>
                  Creating Account...
                </div>
              ) : (
                'Create Account'
              )}
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center mt-6">
          <p className="text-sm text-gray-500">
            © 2024 Plate Recognition System. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;