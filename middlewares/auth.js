const jwt = require('jsonwebtoken');
const User = require('../models/User');

const getAccessTokenSecret = () =>
  process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'Token təqdim edilməyib, girişə icazə verilmir' 
      });
    }

    const decoded = jwt.verify(token, getAccessTokenSecret());
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Token etibarlı deyil' 
      });
    }

    if (!user.isActive) {
      return res.status(401).json({ 
        success: false,
        message: 'İstifadəçi hesabı deaktiv edilib' 
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware xətası:', error.message);
    res.status(401).json({ 
      success: false,
      message: 'Token etibarlı deyil' 
    });
  }
};

module.exports = auth;
