import React from 'react';
import { ChevronDown } from 'lucide-react';

interface FilterBarProps {
  onFilterChange: (filter: string) => void;
  onStatusChange: (status: string) => void;
}

const FilterBar: React.FC<FilterBarProps> = ({ onFilterChange, onStatusChange }) => {
  const handleFilterChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFilterChange(e.target.value);
    console.log('Filter input:', e.target.value);
  };

  const handleStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onStatusChange(e.target.value);
    console.log('Status filter:', e.target.value);
  };

  return (
    <div className="bg-white p-4 sm:p-6 border-b border-gray-200">
      <h2 className="text-base sm:text-lg font-semibold text-gray-900 mb-4">Accounts Awaiting Approval</h2>
      
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-4 sm:space-y-0 sm:space-x-4">
        <div className="flex-1 sm:max-w-md">
          <input
            type="text"
            placeholder="Filter by name or email..."
            onChange={handleFilterChange}
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        
        <div className="relative w-full sm:w-auto">
          <select
            onChange={handleStatusChange}
            className="appearance-none bg-white border border-gray-300 rounded-md px-4 py-2 pr-8 w-full sm:w-auto focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Statuses</option>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
          </select>
          <ChevronDown size={16} className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none" />
        </div>
      </div>
    </div>
  );
};

export default FilterBar;