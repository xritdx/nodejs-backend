const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'İcazə adı tələb olunur'],
    unique: true,
    trim: true
  },
  slug: {
    type: String,
    required: [true, 'İcazə slug tələb olunur'],
    unique: true,
    lowercase: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  resource: {
    type: String,
    required: [true, 'Resurs adı tələb olunur'],
    trim: true
  },
  action: {
    type: String,
    required: [true, 'Əməliyyat adı tələb olunur'],
    trim: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Permission', permissionSchema);
