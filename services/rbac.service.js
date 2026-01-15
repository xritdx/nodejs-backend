const RoleToUserAssignment = require('../models/RoleToUserAssignment');
const PermissionToRoleAssignment = require('../models/PermissionToRoleAssignment');
const Permission = require('../models/Permission');
const Role = require('../models/Role');

/**
 * İstifadəçinin rollarını gətirir
 * @param {string} userId - İstifadəçi ID-si
 * @returns {Promise<Array>} - Rol obyektləri massivi
 */
const getUserRoles = async (userId) => {
  const userRoles = await RoleToUserAssignment.find({ userId }).select('roleId');
  const roleIds = userRoles.map(ur => ur.roleId);

  if (roleIds.length === 0) return [];

  const roles = await Role.find({ _id: { $in: roleIds } });
  return roles;
};

/**
 * İstifadəçinin sahib olduğu bütün icazələri gətirir
 * @param {string} userId - İstifadəçi ID-si
 * @returns {Promise<Array>} - İcazə obyektləri massivi
 */
const getUserPermissions = async (userId) => {
  // 1. İstifadəçinin rollarını tap
  const userRoles = await RoleToUserAssignment.find({ userId }).select('roleId');
  const roleIds = userRoles.map(ur => ur.roleId);

  if (roleIds.length === 0) return [];

  // 2. Bu rollara aid olan icazə ID-lərini tap
  const rolePermissions = await PermissionToRoleAssignment.find({ roleId: { $in: roleIds } }).select('permissionId');
  const permissionIds = rolePermissions.map(rp => rp.permissionId);

  if (permissionIds.length === 0) return [];

  // 3. İcazə detallarını gətir
  const permissions = await Permission.find({ _id: { $in: permissionIds } });
  
  return permissions;
};

/**
 * İstifadəçinin konkret icazəyə sahib olub-olmadığını yoxlayır
 * @param {string} userId - İstifadəçi ID-si
 * @param {string} requiredPermissionSlug - Tələb olunan icazə slug-ı (məs: user.create)
 * @returns {Promise<boolean>}
 */
const hasPermission = async (userId, requiredPermissionSlug) => {
  const permissions = await getUserPermissions(userId);
  return permissions.some(p => p.slug === requiredPermissionSlug);
};

module.exports = {
  getUserRoles,
  getUserPermissions,
  hasPermission
};
