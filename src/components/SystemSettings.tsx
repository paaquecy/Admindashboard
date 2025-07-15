import React, { useState } from 'react';
import { 
  Settings, 
  Palette, 
  Globe, 
  Bell, 
  Link, 
  Database,
  Save,
  ChevronDown,
  Moon,
  Sun,
  Mail,
  MessageSquare,
  Key,
  Calendar,
  HardDrive
} from 'lucide-react';

interface SystemSettingsProps {
  darkMode: boolean;
  onDarkModeToggle: (enabled: boolean) => void;
}

const SystemSettings: React.FC<SystemSettingsProps> = ({ darkMode, onDarkModeToggle }) => {
  // Theme Settings State
  const [darkModeEnabled, setDarkModeEnabled] = useState(darkMode);

  // General Settings State
  const [timezone, setTimezone] = useState('UTC-5 (Eastern Time)');
  const [language, setLanguage] = useState('English');
  const [dateFormat, setDateFormat] = useState('MM/DD/YYYY');

  // Notification Settings State
  const [emailNotificationsEnabled, setEmailNotificationsEnabled] = useState(true);
  const [smsNotificationsEnabled, setSmsNotificationsEnabled] = useState(false);
  const [notificationEmail, setNotificationEmail] = useState('admin@example.com');

  // Integration Settings State
  const [apiKey, setApiKey] = useState('************');
  const [integrationUrl, setIntegrationUrl] = useState('https://api.example.com/integration');

  // Data Management State
  const [dataRetentionDays, setDataRetentionDays] = useState('365');
  const [backupFrequency, setBackupFrequency] = useState('Daily');

  const handleDarkModeToggle = () => {
    const newState = !darkModeEnabled;
    setDarkModeEnabled(newState);
    onDarkModeToggle(newState);
    console.log('Dark Mode toggled to:', newState);
  };

  const handleEmailNotificationsToggle = () => {
    const newState = !emailNotificationsEnabled;
    setEmailNotificationsEnabled(newState);
    console.log('Email Notifications toggled to:', newState);
  };

  const handleSmsNotificationsToggle = () => {
    const newState = !smsNotificationsEnabled;
    setSmsNotificationsEnabled(newState);
    console.log('SMS Notifications toggled to:', newState);
  };

  const handleTimezoneChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setTimezone(e.target.value);
    console.log('Timezone changed to:', e.target.value);
  };

  const handleLanguageChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setLanguage(e.target.value);
    console.log('Language changed to:', e.target.value);
  };

  const handleDateFormatChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setDateFormat(e.target.value);
    console.log('Date Format changed to:', e.target.value);
  };

  const handleNotificationEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setNotificationEmail(e.target.value);
    console.log('Notification Email changed to:', e.target.value);
  };

  const handleApiKeyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setApiKey(e.target.value);
    console.log('API Key changed to:', e.target.value);
  };

  const handleIntegrationUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setIntegrationUrl(e.target.value);
    console.log('Integration URL changed to:', e.target.value);
  };

  const handleDataRetentionChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDataRetentionDays(e.target.value);
    console.log('Data Retention Days changed to:', e.target.value);
  };

  const handleBackupFrequencyChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setBackupFrequency(e.target.value);
    console.log('Backup Frequency changed to:', e.target.value);
  };

  const handleSaveTheme = () => {
    console.log('Save Theme button clicked');
  };

  const handleInitiateManualBackup = () => {
    console.log('Initiate Manual Backup button clicked');
  };

  const handleSaveAllSettings = () => {
    console.log('Save All Settings button clicked');
    console.log('Current settings:', {
      darkModeEnabled,
      timezone,
      language,
      dateFormat,
      emailNotificationsEnabled,
      smsNotificationsEnabled,
      notificationEmail,
      apiKey,
      integrationUrl,
      dataRetentionDays,
      backupFrequency
    });
  };

  const ToggleSwitch: React.FC<{ enabled: boolean; onToggle: () => void }> = ({ enabled, onToggle }) => (
    <button
      onClick={onToggle}
      className={`
        relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
        ${enabled ? 'bg-blue-600' : 'bg-gray-200'}
      `}
    >
      <span
        className={`
          inline-block h-4 w-4 transform rounded-full bg-white transition-transform
          ${enabled ? 'translate-x-6' : 'translate-x-1'}
        `}
      />
    </button>
  );

  return (
    <div className="p-6 space-y-8">
      {/* Theme Settings Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center mb-6">
          <Palette className="w-5 h-5 mr-2 text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-900">Theme Settings</h2>
        </div>

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              {darkModeEnabled ? (
                <Moon className="w-5 h-5 mr-2 text-gray-500" />
              ) : (
                <Sun className="w-5 h-5 mr-2 text-gray-500" />
              )}
              <label className="text-sm font-medium text-gray-700">
                Enable Dark Mode
              </label>
            </div>
            <ToggleSwitch enabled={darkModeEnabled} onToggle={handleDarkModeToggle} />
          </div>

          <div className="pt-4 border-t border-gray-200">
            <button
              onClick={handleSaveTheme}
              className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors font-medium flex items-center"
            >
              <Save size={16} className="mr-2" />
              Save Theme
            </button>
          </div>
        </div>
      </div>

      {/* General Settings Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center mb-6">
          <Globe className="w-5 h-5 mr-2 text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-900">General Settings</h2>
        </div>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Timezone
            </label>
            <div className="relative">
              <select
                value={timezone}
                onChange={handleTimezoneChange}
                className="appearance-none bg-white border border-gray-300 rounded-md px-4 py-2 pr-8 w-full max-w-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="UTC-5 (Eastern Time)">UTC-5 (Eastern Time)</option>
                <option value="UTC-6 (Central Time)">UTC-6 (Central Time)</option>
                <option value="UTC-7 (Mountain Time)">UTC-7 (Mountain Time)</option>
                <option value="UTC-8 (Pacific Time)">UTC-8 (Pacific Time)</option>
                <option value="UTC+0 (GMT)">UTC+0 (GMT)</option>
              </select>
              <ChevronDown size={16} className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none" />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Language
            </label>
            <div className="relative">
              <select
                value={language}
                onChange={handleLanguageChange}
                className="appearance-none bg-white border border-gray-300 rounded-md px-4 py-2 pr-8 w-full max-w-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="English">English</option>
                <option value="Spanish">Spanish</option>
                <option value="French">French</option>
                <option value="German">German</option>
                <option value="Chinese">Chinese</option>
              </select>
              <ChevronDown size={16} className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none" />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Date Format
            </label>
            <div className="relative">
              <select
                value={dateFormat}
                onChange={handleDateFormatChange}
                className="appearance-none bg-white border border-gray-300 rounded-md px-4 py-2 pr-8 w-full max-w-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="MM/DD/YYYY">MM/DD/YYYY</option>
                <option value="DD/MM/YYYY">DD/MM/YYYY</option>
                <option value="YYYY-MM-DD">YYYY-MM-DD</option>
                <option value="DD-MM-YYYY">DD-MM-YYYY</option>
              </select>
              <ChevronDown size={16} className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none" />
            </div>
          </div>
        </div>
      </div>

      {/* Notification Settings Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center mb-6">
          <Bell className="w-5 h-5 mr-2 text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-900">Notification Settings</h2>
        </div>

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Mail className="w-5 h-5 mr-2 text-gray-500" />
              <label className="text-sm font-medium text-gray-700">
                Enable Email Notifications for Violations
              </label>
            </div>
            <ToggleSwitch enabled={emailNotificationsEnabled} onToggle={handleEmailNotificationsToggle} />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <MessageSquare className="w-5 h-5 mr-2 text-gray-500" />
              <label className="text-sm font-medium text-gray-700">
                Enable SMS Notifications for Critical Alerts
              </label>
            </div>
            <ToggleSwitch enabled={smsNotificationsEnabled} onToggle={handleSmsNotificationsToggle} />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Notification Email Address
            </label>
            <input
              type="email"
              value={notificationEmail}
              onChange={handleNotificationEmailChange}
              className="border border-gray-300 rounded-md px-4 py-2 w-full max-w-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>
      </div>

      {/* Integration Settings Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center mb-6">
          <Link className="w-5 h-5 mr-2 text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-900">Integration Settings</h2>
        </div>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              API Key for External Services
            </label>
            <div className="relative">
              <Key className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input
                type="password"
                value={apiKey}
                onChange={handleApiKeyChange}
                className="border border-gray-300 rounded-md pl-10 pr-4 py-2 w-full max-w-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Third-Party Integration URL
            </label>
            <input
              type="url"
              value={integrationUrl}
              onChange={handleIntegrationUrlChange}
              className="border border-gray-300 rounded-md px-4 py-2 w-full max-w-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>
      </div>

      {/* Data Management Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center mb-6">
          <Database className="w-5 h-5 mr-2 text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-900">Data Management</h2>
        </div>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Data Retention Policy (days)
            </label>
            <input
              type="number"
              value={dataRetentionDays}
              onChange={handleDataRetentionChange}
              min="1"
              max="3650"
              className="border border-gray-300 rounded-md px-4 py-2 w-32 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Automatic Backup Frequency
            </label>
            <div className="relative">
              <select
                value={backupFrequency}
                onChange={handleBackupFrequencyChange}
                className="appearance-none bg-white border border-gray-300 rounded-md px-4 py-2 pr-8 w-full max-w-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="Hourly">Hourly</option>
                <option value="Daily">Daily</option>
                <option value="Weekly">Weekly</option>
                <option value="Monthly">Monthly</option>
              </select>
              <ChevronDown size={16} className={`absolute right-2 top-1/2 transform -translate-y-1/2 pointer-events-none ${
                darkMode ? 'text-gray-400' : 'text-gray-400'
              }`} />
            </div>
          </div>

          <div className={`pt-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
            <button
              onClick={handleInitiateManualBackup}
              className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors font-medium flex items-center"
            >
              <HardDrive size={16} className="mr-2" />
              Initiate Manual Backup
            </button>
          </div>
        </div>
      </div>

      {/* Save All Settings Button */}
      <div className={`flex justify-end pt-6 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
        <button
          onClick={handleSaveAllSettings}
          className="px-8 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors font-medium flex items-center text-lg"
        >
          <Save size={20} className="mr-2" />
          Save All Settings
        </button>
      </div>
    </div>
  );
};

export default SystemSettings;