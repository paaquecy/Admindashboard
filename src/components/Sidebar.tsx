import React, { useState } from 'react';
import { 
  LayoutDashboard, 
  Clock, 
  AlertTriangle, 
  Users, 
  Car, 
  BarChart3, 
  Shield, 
  Settings, 
  UserCog, 
  LogOut, 
  Menu,
  X
} from 'lucide-react';

interface SidebarProps {
  activeItem: string;
  onItemClick: (item: string) => void;
  onLogout?: () => void;
  darkMode: boolean;
}

const Sidebar: React.FC<SidebarProps> = ({ activeItem, onItemClick, onLogout, darkMode }) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const menuItems = [
    { id: 'overview', label: 'Overview Dashboard', icon: LayoutDashboard },
    { id: 'pending-approvals', label: 'Pending Approvals', icon: Clock },
    { id: 'violation-management', label: 'Violation Management', icon: AlertTriangle },
    { id: 'user-accounts', label: 'User Account Management', icon: Users },
    { id: 'vehicle-registry', label: 'Data Entry & Vehicle Registry', icon: Car },
    { id: 'analytics', label: 'Analytics & Reporting', icon: BarChart3 },
    { id: 'security', label: 'Security Management', icon: Shield },
    { id: 'admin-controls', label: 'Administrative Controls', icon: UserCog },
    { id: 'system-settings', label: 'System Settings', icon: Settings },
  ];

  const handleLogout = () => {
    console.log('Logout button clicked');
    if (onLogout) {
      onLogout();
    }
  };

  const handleMenuItemClick = (itemId: string) => {
    onItemClick(itemId);
    setIsMobileMenuOpen(false); // Close mobile menu after selection
  };
  return (
    <>
      {/* Mobile overlay */}
      {isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}
      
      {/* Sidebar */}
      <div className={`
        fixed left-0 top-0 h-full bg-white shadow-lg z-50 transition-transform duration-300 ease-in-out
        ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        w-64 flex flex-col lg:static lg:transform-none
      `}>
        {/* Header */}
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h1 className="text-lg lg:text-xl font-bold text-gray-900">Plate Recognition</h1>
            <h1 className="text-xl font-bold text-gray-900">Plate Recognition</h1>
            <button
              onClick={() => setIsMobileMenuOpen(false)}
              className="lg:hidden p-2 rounded-md hover:bg-gray-100"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-6 overflow-y-auto">
          <ul className="space-y-2">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeItem === item.id;
              
              return (
                <li key={item.id}>
                  <button
                    onClick={() => handleMenuItemClick(item.id)}
                    className={`
                      w-full flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors
                      ${isActive 
                        ? 'bg-blue-50 text-blue-700 border-r-2 border-blue-600' 
                        : 'text-gray-700 hover:bg-gray-50'
                      }
                    `}
                  >
                    <Icon size={18} className="mr-3" />
                    <span className="truncate">{item.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* User Profile */}
        <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
          <div className="flex items-center mb-4">
            <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center">
              <span className="text-white font-semibold">AU</span>
            </div>
            <div className="ml-3">
              <p className={`text-sm font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Admin User</p>
              <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Administrator</p>
            </div>
          </div>
          
          <button
            onClick={handleLogout}
            className={`w-full flex px-3 py-2 text-sm font-medium rounded-md transition-colors items-center ${
              darkMode
                ? 'text-red-400 bg-red-900/20 hover:bg-red-900/30'
                : 'text-red-700 bg-red-50 hover:bg-red-100'
            }`}
          >
            <LogOut size={18} className="mr-3" />
            Logout
          </button>
        </div>
      </div>

      {/* Mobile menu button */}
      <button
        onClick={() => setIsMobileMenuOpen(true)}
        className={`
          fixed top-4 left-4 z-40 lg:hidden p-2 bg-white rounded-md shadow-md border border-gray-200
          ${!isMobileMenuOpen ? 'block' : 'hidden'}
        `}
      >
        <Menu size={20} />
      </button>
    </>
  );
};

export default Sidebar;
