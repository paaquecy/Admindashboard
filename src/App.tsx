import React, { useState } from 'react';
import LoginPage from './components/LoginPage';
import RegisterPage from './components/RegisterPage';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import FilterBar from './components/FilterBar';
import PendingApprovalsTable from './components/PendingApprovalsTable';
import ViolationFilterBar from './components/ViolationFilterBar';
import ViolationTable from './components/ViolationTable';
import Dashboard from './components/Dashboard';
import UserAccountManagement from './components/UserAccountManagement';
import VehicleRegistry from './components/VehicleRegistry';
import AnalyticsReporting from './components/AnalyticsReporting';
import SecurityManagement from './components/SecurityManagement';
import AdministrativeControls from './components/AdministrativeControls';
import SystemSettings from './components/SystemSettings';
import AddNewRole from './components/AddNewRole';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showRegister, setShowRegister] = useState(false);
  const [activeItem, setActiveItem] = useState('overview');
  const [darkMode, setDarkMode] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterQuery, setFilterQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  
  // Pending approvals state
  const [pendingApprovals, setPendingApprovals] = useState([
    {
      id: '1',
      userName: 'John Doe',
      email: 'john.doe@example.com',
      role: 'Police Officer',
      requestDate: '2024-07-20',
      accountType: 'police',
      additionalInfo: {
        badgeNumber: 'P12345',
        rank: 'Sergeant',
        station: 'Central Station'
      }
    },
    {
      id: '2',
      userName: 'Jane Smith',
      email: 'jane.smith@example.com',
      role: 'DVLA Officer',
      requestDate: '2024-07-19',
      accountType: 'dvla',
      additionalInfo: {
        idNumber: 'DVLA001',
        position: 'Registration Officer'
      }
    }
  ]);

  // Track approved users who can login
  const [approvedUsers, setApprovedUsers] = useState([
    {
      username: '4231220075',
      password: 'Wattaddo020',
      email: 'approved@dvla.com',
      firstName: 'Approved',
      lastName: 'User',
      role: 'DVLA Officer',
      accountType: 'dvla'
    }
  ]);
  
  // Violation management specific filters
  const [plateNumberFilter, setPlateNumberFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [violationStatusFilter, setViolationStatusFilter] = useState('all');
  const [dateFilter, setDateFilter] = useState('');

  const handleDarkModeToggle = (enabled: boolean) => {
    setDarkMode(enabled);
    console.log('Dark mode toggled to:', enabled);
  };

  const handleItemClick = (item: string) => {
    setActiveItem(item);
    console.log(`Navigation clicked: ${item}`);
  };

  const handleSearch = (query: string) => {
    setSearchQuery(query);
    console.log(`Search query: ${query}`);
  };

  const handleFilterChange = (filter: string) => {
    setFilterQuery(filter);
  };

  const handleStatusChange = (status: string) => {
    setStatusFilter(status);
  };

  const handlePlateNumberChange = (plateNumber: string) => {
    setPlateNumberFilter(plateNumber);
  };

  const handleTypeChange = (type: string) => {
    setTypeFilter(type);
  };

  const handleViolationStatusChange = (status: string) => {
    setViolationStatusFilter(status);
  };

  const handleDateChange = (date: string) => {
    setDateFilter(date);
  };

  const handleLogin = () => {
    setIsLoggedIn(true);
    setShowRegister(false);
    console.log('User logged in successfully');
  };

  const handleShowRegister = () => {
    setShowRegister(true);
    console.log('Navigating to registration page');
  };

  const handleBackToLogin = () => {
    setShowRegister(false);
    console.log('Navigating back to login page');
  };

  const handleRegisterSuccess = () => {
    setShowRegister(false);
    console.log('Registration successful, returning to login');
  };
  
  const handleNewRegistration = (registrationData) => {
    const newApproval = {
      id: String(pendingApprovals.length + 1),
      userName: `${registrationData.firstName} ${registrationData.lastName}`,
      email: registrationData.email,
      role: registrationData.accountType === 'police' ? 'Police Officer' : 'DVLA Officer',
      requestDate: new Date().toISOString().split('T')[0],
      accountType: registrationData.accountType,
      additionalInfo: registrationData.accountType === 'police'
        ? {
            badgeNumber: registrationData.badgeNumber,
            rank: registrationData.rank,
            station: registrationData.station
          }
        : {
            idNumber: registrationData.idNumber,
            position: registrationData.position
          },
      // Store the credentials for later approval
      credentials: {
        username: registrationData.email,
        password: registrationData.password,
        firstName: registrationData.firstName,
        lastName: registrationData.lastName
      }
    };

    setPendingApprovals(prev => [...prev, newApproval]);
    console.log('New registration added to pending approvals:', newApproval);
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setActiveItem('overview'); // Reset to default page
    console.log('User logged out');
  };

  const handleUserApproval = (userId: string, action: 'approve' | 'reject') => {
    const userToProcess = pendingApprovals.find(user => user.id === userId);

    if (!userToProcess) return;

    if (action === 'approve' && userToProcess.credentials) {
      // Add to approved users
      const newApprovedUser = {
        username: userToProcess.credentials.username,
        password: userToProcess.credentials.password,
        email: userToProcess.email,
        firstName: userToProcess.credentials.firstName,
        lastName: userToProcess.credentials.lastName,
        role: userToProcess.role,
        accountType: userToProcess.accountType
      };

      setApprovedUsers(prev => [...prev, newApprovedUser]);
      console.log('User approved and added to approved users:', newApprovedUser);
    }

    // Remove from pending approvals
    setPendingApprovals(prev => prev.filter(user => user.id !== userId));

    const actionText = action === 'approve' ? 'approved' : 'rejected';
    console.log(`User ${userToProcess.userName} has been ${actionText}`);
  };

  const getPageTitle = () => {
    switch (activeItem) {
      case 'overview':
        return 'Overview Dashboard';
      case 'pending-approvals':
        return 'Pending Approvals';
      case 'violation-management':
        return 'Violation Management';
      case 'user-accounts':
        return 'User Account Management';
      case 'vehicle-registry':
        return 'Data Entry & Vehicle Registry';
      case 'analytics':
        return 'Analytics & Reporting';
      case 'security':
        return 'Security Management';
      case 'system-settings':
        return 'System Settings';
      case 'admin-controls':
        return 'Administrative Controls';
      case 'add-new-role':
        return 'Add New Role';
      default:
        return 'Dashboard';
    }
  };

  // Show login page if not logged in
  if (!isLoggedIn) {
    if (showRegister) {
      return (
        <RegisterPage 
          onBackToLogin={handleBackToLogin}
          onRegisterSuccess={handleRegisterSuccess}
          onNewRegistration={handleNewRegistration}
        />
      );
    }
    return (
      <LoginPage
        onLogin={handleLogin}
        onRegister={handleShowRegister}
        approvedUsers={approvedUsers}
        pendingApprovals={pendingApprovals}
      />
    );
  }

  const renderMainContent = () => {
    switch (activeItem) {
      case 'overview':
        return <Dashboard darkMode={darkMode} />;
      case 'pending-approvals':
        return (
          <>
            <FilterBar 
              onFilterChange={handleFilterChange}
              onStatusChange={handleStatusChange}
            />
            
            <PendingApprovalsTable 
              searchQuery={searchQuery}
              filterQuery={filterQuery}
              statusFilter={statusFilter}
              approvals={pendingApprovals}
              setApprovals={setPendingApprovals}
            />
          </>
        );
      case 'violation-management':
        return (
          <>
            <ViolationFilterBar
              onPlateNumberChange={handlePlateNumberChange}
              onTypeChange={handleTypeChange}
              onStatusChange={handleViolationStatusChange}
              onDateChange={handleDateChange}
            />
            
            <ViolationTable
              searchQuery={searchQuery}
              plateNumberFilter={plateNumberFilter}
              typeFilter={typeFilter}
              statusFilter={violationStatusFilter}
              dateFilter={dateFilter}
            />
          </>
        );
      case 'user-accounts':
        return <UserAccountManagement searchQuery={searchQuery} />;
      case 'vehicle-registry':
        return <VehicleRegistry searchQuery={searchQuery} />;
      case 'analytics':
        return <AnalyticsReporting />;
      case 'security':
        return <SecurityManagement />;
      case 'system-settings':
        return <SystemSettings onDarkModeToggle={handleDarkModeToggle} darkMode={darkMode} />;
      case 'admin-controls':
        return <AdministrativeControls onNavigate={setActiveItem} />;
      case 'add-new-role':
        return <AddNewRole onNavigate={setActiveItem} />;
      default:
        return (
          <div className="p-6 text-center text-gray-500">
            Select a menu item to view content
          </div>
        );
    }
  };
  return (
    <div className={`min-h-screen font-['Inter'] flex ${darkMode ? 'bg-gray-900' : 'bg-gray-100'}`}>
      <Sidebar 
        activeItem={activeItem} 
        onItemClick={handleItemClick} 
        onLogout={handleLogout} 
        darkMode={darkMode}
      />
      
      <div className="flex-1 lg:ml-0">
        <TopBar title={getPageTitle()} onSearch={handleSearch} darkMode={darkMode} />
        
        <main className={`min-h-[calc(100vh-4rem)] ${darkMode ? 'bg-gray-900' : 'bg-gray-100'}`}>
          {renderMainContent()}
        </main>
      </div>
    </div>
  );
}

export default App;
