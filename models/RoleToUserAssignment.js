const mongoose = require('mongoose');

const roleToUserAssignmentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'İstifadəçi ID tələb olunur']
  },
  roleId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    required: [true, 'Rol ID tələb olunur']
  }
}, {
  timestamps: true
});

// Eyni istifadəçiyə eyni rolun təkrar verilməsinin qarşısını almaq üçün unikal indeks
roleToUserAssignmentSchema.index({ userId: 1, roleId: 1 }, { unique: true });

module.exports = mongoose.model('RoleToUserAssignment', roleToUserAssignmentSchema);
