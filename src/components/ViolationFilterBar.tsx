import React from 'react';
import { ChevronDown, Calendar } from 'lucide-react';

interface ViolationFilterBarProps {
  onPlateNumberChange: (plateNumber: string) => void;
  onTypeChange: (type: string) => void;
  onStatusChange: (status: string) => void;
  onDateChange: (date: string) => void;
}

const ViolationFilterBar: React.FC<ViolationFilterBarProps> = ({
  onPlateNumberChange,
  onTypeChange,
  onStatusChange,
  onDateChange
}) => {
  const handlePlateNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onPlateNumberChange(e.target.value);
    console.log('Plate number filter:', e.target.value);
  };

  const handleTypeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onTypeChange(e.target.value);
    console.log('Type filter:', e.target.value);
  };

  const handleStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onStatusChange(e.target.value);
    console.log('Status filter:', e.target.value);
  };

  const handleDateChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onDateChange(e.target.value);
    console.log('Date filter:', e.target.value);
  };

  return (
    <div className="bg-white p-4 sm:p-6 border-b border-gray-200">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="flex-1">
          <input
            type="text"
            placeholder="Filter by Plate Number..."
            onChange={handlePlateNumberChange}
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        
        <div className="relative">
          <select
            onChange={handleTypeChange}
            className="appearance-none bg-white border border-gray-300 rounded-md px-4 py-2 pr-8 w-full focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Types</option>
            <option value="speeding">Speeding</option>
            <option value="parking">Parking</option>
            <option value="red-light">Red Light</option>
            <option value="stop-sign">Stop Sign</option>
            <option value="no-parking">No Parking</option>
          </select>
          <ChevronDown size={16} className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none" />
        </div>
        
        <div className="relative">
          <select
            onChange={handleStatusChange}
            className="appearance-none bg-white border border-gray-300 rounded-md px-4 py-2 pr-8 w-full focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="pending">Pending</option>
            <option value="resolved">Resolved</option>
          </select>
          <ChevronDown size={16} className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none" />
        </div>
        
        <div className="relative">
          <input
            type="date"
            onChange={handleDateChange}
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          <Calendar size={16} className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none" />
        </div>
      </div>
    </div>
  );
};

export default ViolationFilterBar;