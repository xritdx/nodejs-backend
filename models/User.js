const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const personalDataSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Ad tələb olunur'],
    trim: true,
    maxlength: [50, 'Ad 50 simvoldan çox ola bilməz']
  },
  surname: {
    type: String,
    required: [true, 'Soyad tələb olunur'],
    trim: true,
    maxlength: [50, 'Soyad 50 simvoldan çox ola bilməz']
  },
  patronymic: {
    type: String,
    required: [true, 'Patronymic tələb olunur'],
    trim: true,
    maxlength: [50, 'Patronymic 50 simvoldan çox ola bilməz']
  },
  gender: {
    type: String,
    required: [true, 'Cinsiyyət tələb olunur'],
    enum: ['male', 'female'],
    default: 'male'
  },
  martialStatus: {
    type: String,
    required: [true, 'Ailə vəziyyəti tələb olunur'],
    enum: ['single', 'married'],
    default: 'single'
  }
});

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'E-poçt tələb olunur'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Zəhmət olmasa düzgün e-poçt ünvanı daxil edin'
    ]
  },
  password: {
    type: String,
    required: [true, 'Şifrə tələb olunur'],
    minlength: [8, 'Şifrə ən azı 8 simvoldan ibarət olmalıdır']
  },
  personalData: personalDataSchema,
  isActive: {
    type: Boolean,
    default: true
  },
  tokenVersion: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost of 12
    const hashedPassword = await bcrypt.hash(this.password, 12);
    this.password = hashedPassword;
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  return userObject;
};

module.exports = mongoose.model('User', userSchema);
