import React, { useState } from 'react';
import { 
  UserCog, 
  Save, 
  X, 
  ArrowLeft,
  BarChart3,
  Users,
  AlertTriangle,
  Car,
  Shield,
  Settings
} from 'lucide-react';

interface PermissionGroup {
  id: string;
  title: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  permissions: {
    id: string;
    label: string;
    checked: boolean;
  }[];
}

interface AddNewRoleProps {
  onNavigate?: (page: string) => void;
}

const AddNewRole: React.FC<AddNewRoleProps> = ({ onNavigate }) => {
  const [roleName, setRoleName] = useState('');
  const [description, setDescription] = useState('');
  
  const [permissionGroups, setPermissionGroups] = useState<PermissionGroup[]>([
    {
      id: 'dashboard',
      title: 'Dashboard & Reporting',
      icon: BarChart3,
      permissions: [
        { id: 'view_overview_dashboard', label: 'View Overview Dashboard', checked: false },
        { id: 'view_analytics_reports', label: 'View Analytics & Reports', checked: false },
        { id: 'generate_custom_reports', label: 'Generate Custom Reports', checked: false }
      ]
    },
    {
      id: 'users',
      title: 'User & Approvals',
      icon: Users,
      permissions: [
        { id: 'view_user_accounts', label: 'View User Accounts', checked: false },
        { id: 'manage_user_accounts', label: 'Manage User Accounts (Add, Edit, Deactivate)', checked: false },
        { id: 'view_pending_approvals', label: 'View Pending Approvals', checked: false },
        { id: 'approve_reject_signups', label: 'Approve/Reject User Sign-ups', checked: false }
      ]
    },
    {
      id: 'violations',
      title: 'Violation Management',
      icon: AlertTriangle,
      permissions: [
        { id: 'view_violations', label: 'View Violations', checked: false },
        { id: 'resolve_violations', label: 'Resolve Violations', checked: false },
        { id: 'edit_violation_details', label: 'Edit Violation Details', checked: false },
        { id: 'delete_violations', label: 'Delete Violations', checked: false }
      ]
    },
    {
      id: 'registry',
      title: 'Data Entry & Registry',
      icon: Car,
      permissions: [
        { id: 'view_vehicle_registry', label: 'View Vehicle Registry', checked: false },
        { id: 'add_vehicle_records', label: 'Add New Vehicle Records', checked: false },
        { id: 'edit_vehicle_records', label: 'Edit Vehicle Records', checked: false },
        { id: 'delete_vehicle_records', label: 'Delete Vehicle Records', checked: false }
      ]
    },
    {
      id: 'security',
      title: 'System & Security',
      icon: Shield,
      permissions: [
        { id: 'view_system_settings', label: 'View System Settings', checked: false },
        { id: 'manage_system_settings', label: 'Manage System Settings', checked: false },
        { id: 'view_security_settings', label: 'View Security Settings', checked: false },
        { id: 'manage_security_settings', label: 'Manage Security Settings', checked: false },
        { id: 'view_audit_log', label: 'View Audit Log', checked: false }
      ]
    },
    {
      id: 'administrative',
      title: 'Administrative',
      icon: Settings,
      permissions: [
        { id: 'view_admin_controls', label: 'View Administrative Controls', checked: false },
        { id: 'manage_roles_permissions', label: 'Manage Roles & Permissions', checked: false },
        { id: 'view_system_health', label: 'View System Health', checked: false }
      ]
    }
  ]);

  const handleRoleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setRoleName(e.target.value);
    console.log('Role Name changed to:', e.target.value);
  };

  const handleDescriptionChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setDescription(e.target.value);
    console.log('Description changed to:', e.target.value);
  };

  const handlePermissionChange = (groupId: string, permissionId: string, checked: boolean) => {
    setPermissionGroups(prev => 
      prev.map(group => 
        group.id === groupId 
          ? {
              ...group,
              permissions: group.permissions.map(permission =>
                permission.id === permissionId
                  ? { ...permission, checked }
                  : permission
              )
            }
          : group
      )
    );
    console.log(`Permission ${permissionId} in group ${groupId} changed to:`, checked);
  };

  const handleSelectAllInGroup = (groupId: string, selectAll: boolean) => {
    setPermissionGroups(prev => 
      prev.map(group => 
        group.id === groupId 
          ? {
              ...group,
              permissions: group.permissions.map(permission => ({
                ...permission,
                checked: selectAll
              }))
            }
          : group
      )
    );
    console.log(`All permissions in group ${groupId} set to:`, selectAll);
  };

  const handleCancel = () => {
    console.log('Cancel button clicked');
    // Navigate back to Administrative Controls
    if (onNavigate) {
      onNavigate('admin-controls');
    }
    // Reset form
    setRoleName('');
    setDescription('');
    setPermissionGroups(prev => 
      prev.map(group => ({
        ...group,
        permissions: group.permissions.map(permission => ({
          ...permission,
          checked: false
        }))
      }))
    );
  };

  const handleSaveRole = () => {
    console.log('Save Role button clicked');
    console.log('Role Data:', {
      roleName,
      description,
      permissions: permissionGroups.reduce((acc, group) => {
        const checkedPermissions = group.permissions
          .filter(p => p.checked)
          .map(p => p.id);
        if (checkedPermissions.length > 0) {
          acc[group.id] = checkedPermissions;
        }
        return acc;
      }, {} as Record<string, string[]>)
    });
    
    // After saving, navigate back to Administrative Controls
    if (onNavigate) {
      onNavigate('admin-controls');
    }
  };

  const getGroupCheckedCount = (group: PermissionGroup) => {
    return group.permissions.filter(p => p.checked).length;
  };

  const isGroupFullyChecked = (group: PermissionGroup) => {
    return group.permissions.every(p => p.checked);
  };

  const isGroupPartiallyChecked = (group: PermissionGroup) => {
    const checkedCount = getGroupCheckedCount(group);
    return checkedCount > 0 && checkedCount < group.permissions.length;
  };

  return (
    <div className="p-6 space-y-8">
      {/* Header with Back Navigation */}
      <div className="flex items-center space-x-4 mb-6">
        <button 
          onClick={() => onNavigate && onNavigate('admin-controls')}
          className="p-2 hover:bg-gray-100 rounded-md transition-colors"
        >
          <ArrowLeft size={20} className="text-gray-600" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Add New Role</h1>
          <p className="text-sm text-gray-600 mt-1">Create a new role and define its permissions</p>
        </div>
      </div>

      {/* Role Details Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center mb-6">
          <UserCog className="w-5 h-5 mr-2 text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-900">Role Details</h2>
        </div>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Role Name
            </label>
            <input
              type="text"
              value={roleName}
              onChange={handleRoleNameChange}
              placeholder="e.g., Editor, Auditor"
              className="w-full max-w-md px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Description
            </label>
            <textarea
              value={description}
              onChange={handleDescriptionChange}
              placeholder="Brief description of the role's responsibilities"
              rows={3}
              className="w-full max-w-2xl px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
            />
          </div>
        </div>
      </div>

      {/* Permissions Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center mb-6">
          <Shield className="w-5 h-5 mr-2 text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-900">Permissions</h2>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {permissionGroups.map((group) => {
            const Icon = group.icon;
            const checkedCount = getGroupCheckedCount(group);
            const isFullyChecked = isGroupFullyChecked(group);
            const isPartiallyChecked = isGroupPartiallyChecked(group);

            return (
              <div key={group.id} className="bg-gray-50 rounded-lg p-4 border border-gray-200">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center">
                    <Icon size={18} className="text-gray-600 mr-2" />
                    <h3 className="font-medium text-gray-900">{group.title}</h3>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-gray-500">
                      {checkedCount}/{group.permissions.length}
                    </span>
                    <button
                      onClick={() => handleSelectAllInGroup(group.id, !isFullyChecked)}
                      className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                    >
                      {isFullyChecked ? 'Deselect All' : 'Select All'}
                    </button>
                  </div>
                </div>

                <div className="space-y-3">
                  {group.permissions.map((permission) => (
                    <label key={permission.id} className="flex items-start space-x-3 cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={permission.checked}
                        onChange={(e) => handlePermissionChange(group.id, permission.id, e.target.checked)}
                        className="mt-0.5 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 focus:ring-2"
                      />
                      <span className="text-sm text-gray-700 group-hover:text-gray-900 leading-5">
                        {permission.label}
                      </span>
                    </label>
                  ))}
                </div>

                {/* Progress indicator */}
                {checkedCount > 0 && (
                  <div className="mt-4 pt-3 border-t border-gray-200">
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 bg-gray-200 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full transition-all duration-300 ${
                            isFullyChecked ? 'bg-green-500' : 'bg-blue-500'
                          }`}
                          style={{ width: `${(checkedCount / group.permissions.length) * 100}%` }}
                        />
                      </div>
                      <span className={`text-xs font-medium ${
                        isFullyChecked ? 'text-green-600' : 'text-blue-600'
                      }`}>
                        {Math.round((checkedCount / group.permissions.length) * 100)}%
                      </span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
        <button
          onClick={handleCancel}
          className="px-6 py-2 text-blue-600 bg-transparent border border-blue-600 rounded-md hover:bg-blue-50 transition-colors font-medium flex items-center"
        >
          <X size={16} className="mr-2" />
          Cancel
        </button>
        <button
          onClick={handleSaveRole}
          disabled={!roleName.trim() || !description.trim()}
          className={`px-6 py-2 rounded-md font-medium flex items-center transition-colors ${
            !roleName.trim() || !description.trim()
              ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
        >
          <Save size={16} className="mr-2" />
          Save Role
        </button>
      </div>

      {/* Summary Panel */}
      {(roleName || description || permissionGroups.some(g => getGroupCheckedCount(g) > 0)) && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="font-medium text-blue-900 mb-2">Role Summary</h3>
          <div className="space-y-2 text-sm">
            {roleName && (
              <p><span className="font-medium text-blue-800">Name:</span> {roleName}</p>
            )}
            {description && (
              <p><span className="font-medium text-blue-800">Description:</span> {description}</p>
            )}
            <div>
              <span className="font-medium text-blue-800">Permissions:</span>
              <div className="mt-1 space-y-1">
                {permissionGroups.map(group => {
                  const checkedCount = getGroupCheckedCount(group);
                  if (checkedCount > 0) {
                    return (
                      <div key={group.id} className="flex items-center space-x-2">
                        <span className="text-blue-700">{group.title}:</span>
                        <span className="text-blue-600">{checkedCount} permission{checkedCount !== 1 ? 's' : ''}</span>
                      </div>
                    );
                  }
                  return null;
                })}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AddNewRole;