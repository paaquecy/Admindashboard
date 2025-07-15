import React, { useState, useMemo } from 'react';

interface Violation {
  id: string;
  plateNumber: string;
  type: string;
  dateTime: string;
  location: string;
  status: 'open' | 'pending' | 'resolved';
}

interface ViolationTableProps {
  searchQuery: string;
  plateNumberFilter: string;
  typeFilter: string;
  statusFilter: string;
  dateFilter: string;
}

const ViolationTable: React.FC<ViolationTableProps> = ({
  searchQuery,
  plateNumberFilter,
  typeFilter,
  statusFilter,
  dateFilter
}) => {
  const [violations, setViolations] = useState<Violation[]>([
    {
      id: 'VIO001',
      plateNumber: 'ABC-123',
      type: 'Speeding',
      dateTime: '2023-10-26 10:30 AM',
      location: 'Main St. & Oak Ave.',
      status: 'open'
    },
    {
      id: 'VIO002',
      plateNumber: 'XYZ-789',
      type: 'Parking',
      dateTime: '2023-10-25 02:15 PM',
      location: 'Parking Lot B',
      status: 'pending'
    },
    {
      id: 'VIO003',
      plateNumber: 'DEF-456',
      type: 'Red Light',
      dateTime: '2023-10-24 09:00 AM',
      location: 'Elm St. & Pine Ave.',
      status: 'open'
    },
    {
      id: 'VIO004',
      plateNumber: 'GHI-012',
      type: 'Speeding',
      dateTime: '2023-10-23 04:45 PM',
      location: 'Highway 101',
      status: 'resolved'
    },
    {
      id: 'VIO005',
      plateNumber: 'JKL-345',
      type: 'Parking',
      dateTime: '2023-10-22 11:00 AM',
      location: 'Downtown Area',
      status: 'open'
    }
  ]);

  const filteredViolations = useMemo(() => {
    return violations.filter(violation => {
      const matchesSearch = searchQuery === '' || 
        violation.plateNumber.toLowerCase().includes(searchQuery.toLowerCase()) ||
        violation.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        violation.location.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesPlateNumber = plateNumberFilter === '' ||
        violation.plateNumber.toLowerCase().includes(plateNumberFilter.toLowerCase());
      
      const matchesType = typeFilter === 'all' || typeFilter === '' ||
        violation.type.toLowerCase().replace(' ', '-') === typeFilter;
      
      const matchesStatus = statusFilter === 'all' || statusFilter === '' ||
        violation.status === statusFilter;
      
      const matchesDate = dateFilter === '' ||
        violation.dateTime.includes(dateFilter);
      
      return matchesSearch && matchesPlateNumber && matchesType && matchesStatus && matchesDate;
    });
  }, [violations, searchQuery, plateNumberFilter, typeFilter, statusFilter, dateFilter]);

  const handleResolve = (violation: Violation) => {
    console.log(`Resolve clicked for #${violation.id}`);
    setViolations(prev => 
      prev.map(v => 
        v.id === violation.id 
          ? { ...v, status: 'resolved' as const }
          : v
      )
    );
  };

  const handleViewDetails = (violation: Violation) => {
    console.log(`View Details clicked for #${violation.id}`);
  };

  const getStatusBadge = (status: string) => {
    const baseClasses = "inline-flex px-2 py-1 text-xs font-semibold rounded-full uppercase";
    
    switch (status) {
      case 'open':
        return `${baseClasses} bg-red-100 text-red-800`;
      case 'pending':
        return `${baseClasses} bg-yellow-100 text-yellow-800`;
      case 'resolved':
        return `${baseClasses} bg-green-100 text-green-800`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  return (
    <div className="bg-white overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                VIOLATION ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                PLATE NUMBER
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                TYPE
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                DATE/TIME
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                LOCATION
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                STATUS
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                ACTIONS
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredViolations.map((violation, index) => (
              <tr 
                key={violation.id}
                className={`hover:bg-gray-50 transition-colors ${
                  index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
                }`}
              >
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-medium text-gray-900">
                    #{violation.id}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-medium text-gray-900">
                    {violation.plateNumber}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">
                    {violation.type}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">
                    {violation.dateTime}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">
                    {violation.location}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={getStatusBadge(violation.status)}>
                    {violation.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <div className="flex space-x-2">
                    <button
                      onClick={() => handleResolve(violation)}
                      disabled={violation.status === 'resolved'}
                      className={`px-3 py-1 text-sm rounded-md transition-colors ${
                        violation.status === 'resolved'
                          ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                          : 'bg-green-600 text-white hover:bg-green-700'
                      }`}
                    >
                      Resolve
                    </button>
                    <button
                      onClick={() => handleViewDetails(violation)}
                      className="px-3 py-1 bg-blue-600 text-white text-sm rounded-md hover:bg-blue-700 transition-colors"
                    >
                      View Details
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        {filteredViolations.length === 0 && (
          <div className="text-center py-8 text-gray-500">
            No violations found matching the current filters.
          </div>
        )}
      </div>
    </div>
  );
};

export default ViolationTable;