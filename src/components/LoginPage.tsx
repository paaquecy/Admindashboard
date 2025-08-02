import React, { useState } from 'react';
import { 
  Eye, 
  EyeOff, 
  ArrowRight, 
  Info, 
  User, 
  Shield,
  Lock,
  UserCheck
} from 'lucide-react';

interface LoginPageProps {
  onLogin: () => void;
  onRegister: () => void;
  approvedUsers: Array<{
    username: string;
    password: string;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
    accountType: string;
  }>;
  pendingApprovals: Array<{
    id: string;
    userName: string;
    email: string;
    credentials?: {
      username: string;
      password: string;
    };
  }>;
}

const LoginPage: React.FC<LoginPageProps> = ({ onLogin, onRegister, approvedUsers, pendingApprovals }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUsername(e.target.value);
    console.log('Username changed to:', e.target.value);
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    console.log('Password changed');
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
    console.log('Password visibility toggled to:', !showPassword);
  };

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    console.log('Login button clicked');
    console.log('Login attempt with username:', username);
    
    if (!username || !password) {
      alert('Please enter both username and password');
      return;
    }

    // Check if user is in approved users list
    const approvedUser = approvedUsers.find(user =>
      (user.username === username || user.email === username) && user.password === password
    );

    if (approvedUser) {
      console.log('Login successful - approved user authenticated');
      onLogin();
      return;
    }

    // Check if user is in pending approvals
    const pendingUser = pendingApprovals.find(user =>
      user.credentials && (user.credentials.username === username || user.email === username)
    );

    if (pendingUser) {
      // Check if password matches for pending user
      if (pendingUser.credentials && pendingUser.credentials.password === password) {
        alert('Your account is pending admin approval. Please wait for approval before logging in.');
      } else {
        alert('Invalid credentials. Please check your username and password.');
      }
      console.log('Login failed - user pending approval or invalid password');
      return;
    }

    // No user found in approved or pending
    alert('Invalid credentials. Please check your username and password.');
    console.log('Login failed - user not found');
  };

  const handleRegisterClick = () => {
    console.log('Register link clicked');
    onRegister();
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4 font-['Inter']">
      <div className="w-full max-w-sm sm:max-w-md">
        {/* Main Login Card */}
        <div className="bg-white rounded-lg shadow-lg p-6 sm:p-8 mb-6 sm:mb-8">
          {/* Header */}
          <div className="text-center mb-6 sm:mb-8">
            <div className="flex items-center justify-center mb-4">
              <Shield className="w-8 h-8 text-blue-600 mr-2" />
              <h1 className="text-xl sm:text-2xl font-bold text-gray-900">
                Plate Recognition System
              </h1>
            </div>
            <h2 className="text-base sm:text-lg font-semibold text-gray-800 mb-2">
              Login to Plate Recognition System
            </h2>
            <p className="text-sm text-gray-600">
              Secure access for authorized personnel
            </p>
          </div>

          {/* Login Form */}
          <form onSubmit={handleLogin} className="space-y-4 sm:space-y-6">
            {/* Username Field */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Username / ID
              </label>
              <div className="relative">
                <User className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  value={username}
                  onChange={handleUsernameChange}
                  placeholder="Enter your username or ID"
                  className="w-full pl-10 pr-4 py-2 sm:py-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                  required
                />
              </div>
            </div>

            {/* Password Field */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <div className="relative">
                <Lock className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={handlePasswordChange}
                  placeholder="Enter your password"
                  className="w-full pl-10 pr-12 py-2 sm:py-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
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
            </div>

            {/* Login Button */}
            <button
              type="submit"
              className="w-full bg-blue-600 text-white py-2 sm:py-3 px-4 rounded-md hover:bg-blue-700 transition-colors font-medium flex items-center justify-center group"
            >
              Login
              <ArrowRight size={20} className="ml-2 group-hover:translate-x-1 transition-transform" />
            </button>
          </form>

          {/* Informative Text */}
          <div className="mt-4 sm:mt-6 space-y-2">
            <div className="flex items-center text-sm text-gray-500">
              <Info size={16} className="mr-2 text-blue-500" />
              <span>Passwords are case-sensitive.</span>
            </div>
            <div className="flex items-center text-sm text-gray-500">
              <Info size={16} className="mr-2 text-yellow-500" />
              <span>Account locks after 5 failed attempts.</span>
            </div>
            <div className="flex items-center text-sm text-gray-500">
              <Info size={16} className="mr-2 text-red-500" />
              <span>Session expires after 30 minutes of inactivity.</span>
            </div>
          </div>

          {/* Registration Link */}
          <div className="mt-4 sm:mt-6 text-center">
            <p className="text-sm text-gray-600">
              New user?{' '}
              <button
                onClick={handleRegisterClick}
                className="text-blue-600 hover:text-blue-800 hover:underline font-medium transition-colors"
              >
                Register here
              </button>
            </p>
          </div>
        </div>

        {/* Authorized User Roles Section */}
        <div className="bg-white rounded-lg shadow-lg p-4 sm:p-6">
          <h3 className="text-center font-semibold text-gray-800 mb-4">
            Authorized User Roles:
          </h3>
          <div className="space-y-3">
            <div className="flex items-center justify-center">
              <UserCheck size={18} className="mr-3 text-blue-600" />
              <span className="text-gray-700 font-medium">DVLA Officer</span>
            </div>
            <div className="flex items-center justify-center">
              <Shield size={18} className="mr-3 text-purple-600" />
              <span className="text-gray-700 font-medium">Administrator</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-4 sm:mt-6">
          <p className="text-xs text-gray-500">
            © 2024 Plate Recognition System. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
