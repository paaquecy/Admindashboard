import React, { useState } from 'react';
import { 
  BarChart3, 
  TrendingUp, 
  Users, 
  Car, 
  AlertTriangle,
  FileText,
  Download,
  Calendar,
  Activity,
  PieChart,
  LineChart
} from 'lucide-react';

const AnalyticsReporting: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState('');

  const kpiData = [
    {
      value: '1,234',
      label: 'Total Vehicle Scans',
      icon: Car,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50'
    },
    {
      value: '87',
      label: 'Total Violations',
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-50'
    },
    {
      value: '56',
      label: 'Active Users',
      icon: Users,
      color: 'text-green-600',
      bgColor: 'bg-green-50'
    },
    {
      value: '450',
      label: 'Registered Vehicles',
      icon: Car,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50'
    }
  ];

  const recentReports = [
    {
      title: 'Violation Summary - Q1 2024',
      date: '2024-03-31',
      type: 'Quarterly Report'
    },
    {
      title: 'Daily Scan Report - 2024-04-20',
      date: '2024-04-20',
      type: 'Daily Report'
    },
    {
      title: 'User Login Activity - April',
      date: '2024-04-19',
      type: 'Activity Report'
    },
    {
      title: 'Vehicle Registration Summary',
      date: '2024-04-18',
      type: 'Registry Report'
    },
    {
      title: 'System Performance Metrics',
      date: '2024-04-17',
      type: 'Performance Report'
    }
  ];

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
    console.log('Search query:', e.target.value);
  };

  const handleGenerateViolationReport = () => {
    console.log('Generate Violation Report clicked');
  };

  const handleExportVehicleRegistry = () => {
    console.log('Export Vehicle Registry clicked');
  };

  const handleUserActivityLog = () => {
    console.log('User Activity Log clicked');
  };

  const handleViewReport = (reportTitle: string) => {
    console.log(`View Report clicked: ${reportTitle}`);
  };

  const handleDownloadReport = (reportTitle: string) => {
    console.log(`Download Report clicked: ${reportTitle}`);
  };

  return (
    <div className="p-6 space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {kpiData.map((kpi, index) => {
          const Icon = kpi.icon;
          return (
            <div key={index} className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-gray-900">{kpi.value}</p>
                  <p className="text-sm text-gray-600 mt-1">{kpi.label}</p>
                </div>
                <div className={`p-3 rounded-full ${kpi.bgColor} ${kpi.color}`}>
                  <Icon size={24} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Violation Trends */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-4">
            <TrendingUp className="w-5 h-5 text-gray-500 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">Violation Trends</h2>
          </div>
          <div className="h-64 bg-gray-100 rounded-lg flex items-center justify-center border-2 border-dashed border-gray-300">
            <div className="text-center">
              <LineChart className="w-12 h-12 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500 font-medium">Line Chart: Violations Over Time</p>
              <p className="text-sm text-gray-400 mt-1">Chart visualization will be displayed here</p>
            </div>
          </div>
        </div>

        {/* Vehicle Scan Activity */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-4">
            <BarChart3 className="w-5 h-5 text-gray-500 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">Vehicle Scan Activity</h2>
          </div>
          <div className="h-64 bg-gray-100 rounded-lg flex items-center justify-center border-2 border-dashed border-gray-300">
            <div className="text-center">
              <BarChart3 className="w-12 h-12 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500 font-medium">Bar Chart: Scans by Vehicle Type</p>
              <p className="text-sm text-gray-400 mt-1">Chart visualization will be displayed here</p>
            </div>
          </div>
        </div>
      </div>

      {/* Additional Analytics Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* System Performance */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-4">
            <Activity className="w-5 h-5 text-gray-500 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">System Performance</h2>
          </div>
          <div className="h-48 bg-gray-100 rounded-lg flex items-center justify-center border-2 border-dashed border-gray-300">
            <div className="text-center">
              <Activity className="w-10 h-10 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500 font-medium">Performance Metrics</p>
              <p className="text-xs text-gray-400 mt-1">Real-time system data</p>
            </div>
          </div>
        </div>

        {/* User Activity Distribution */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-4">
            <PieChart className="w-5 h-5 text-gray-500 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">User Activity Distribution</h2>
          </div>
          <div className="h-48 bg-gray-100 rounded-lg flex items-center justify-center border-2 border-dashed border-gray-300">
            <div className="text-center">
              <PieChart className="w-10 h-10 text-gray-400 mx-auto mb-2" />
              <p className="text-gray-500 font-medium">Pie Chart: User Roles</p>
              <p className="text-xs text-gray-400 mt-1">Activity by user type</p>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-4">
            <BarChart3 className="w-5 h-5 text-gray-500 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">Quick Stats</h2>
          </div>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Today's Scans</span>
              <span className="text-lg font-semibold text-gray-900">127</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">New Violations</span>
              <span className="text-lg font-semibold text-red-600">8</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Resolved Today</span>
              <span className="text-lg font-semibold text-green-600">15</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Active Sessions</span>
              <span className="text-lg font-semibold text-blue-600">23</span>
            </div>
          </div>
        </div>
      </div>

      {/* Reports & Exports and Recent Reports Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Reports & Exports */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-6">
            <FileText className="w-5 h-5 text-gray-500 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">Reports & Exports</h2>
          </div>
          <div className="space-y-4">
            <button
              onClick={handleGenerateViolationReport}
              className="w-full px-4 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors font-medium flex items-center justify-center"
            >
              <FileText size={16} className="mr-2" />
              Generate Violation Report
            </button>
            <button
              onClick={handleExportVehicleRegistry}
              className="w-full px-4 py-3 bg-blue-50 text-blue-600 border border-blue-200 rounded-md hover:bg-blue-100 transition-colors font-medium flex items-center justify-center"
            >
              <Download size={16} className="mr-2" />
              Export Vehicle Registry
            </button>
            <button
              onClick={handleUserActivityLog}
              className="w-full px-4 py-3 bg-blue-50 text-blue-600 border border-blue-200 rounded-md hover:bg-blue-100 transition-colors font-medium flex items-center justify-center"
            >
              <Activity size={16} className="mr-2" />
              User Activity Log
            </button>
          </div>
          
          {/* Additional Export Options */}
          <div className="mt-6 pt-6 border-t border-gray-200">
            <h3 className="text-sm font-medium text-gray-900 mb-3">Quick Exports</h3>
            <div className="grid grid-cols-2 gap-2">
              <button className="px-3 py-2 text-xs bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors">
                CSV Export
              </button>
              <button className="px-3 py-2 text-xs bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors">
                PDF Report
              </button>
              <button className="px-3 py-2 text-xs bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors">
                Excel Export
              </button>
              <button className="px-3 py-2 text-xs bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors">
                JSON Data
              </button>
            </div>
          </div>
        </div>

        {/* Recent Reports */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center mb-6">
            <Calendar className="w-5 h-5 text-gray-500 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">Recent Reports</h2>
          </div>
          <div className="space-y-3">
            {recentReports.map((report, index) => (
              <div key={index} className="flex items-center justify-between p-3 rounded-md border border-gray-100 hover:bg-gray-50 transition-colors">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">
                    {report.title}
                  </p>
                  <div className="flex items-center mt-1 space-x-2">
                    <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
                      {report.type}
                    </span>
                    <span className="text-xs text-gray-500">{report.date}</span>
                  </div>
                </div>
                <div className="flex space-x-2 ml-4">
                  <button
                    onClick={() => handleViewReport(report.title)}
                    className="p-2 text-gray-400 hover:text-blue-600 transition-colors"
                    title="View Report"
                  >
                    <FileText size={16} />
                  </button>
                  <button
                    onClick={() => handleDownloadReport(report.title)}
                    className="p-2 text-gray-400 hover:text-green-600 transition-colors"
                    title="Download Report"
                  >
                    <Download size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-gray-200">
            <button className="w-full text-sm text-blue-600 hover:text-blue-800 font-medium transition-colors">
              View All Reports →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AnalyticsReporting;