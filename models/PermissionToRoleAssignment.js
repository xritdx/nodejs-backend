const mongoose = require('mongoose');

const permissionToRoleAssignmentSchema = new mongoose.Schema({
  roleId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    required: [true, 'Rol ID tələb olunur']
  },
  permissionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission',
    required: [true, 'İcazə ID tələb olunur']
  }
}, {
  timestamps: true
});

// Eyni rola eyni icazənin təkrar verilməsinin qarşısını almaq üçün unikal indeks
permissionToRoleAssignmentSchema.index({ roleId: 1, permissionId: 1 }, { unique: true });

module.exports = mongoose.model('PermissionToRoleAssignment', permissionToRoleAssignmentSchema);
