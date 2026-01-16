const jwt = require('jsonwebtoken');
const User = require('../models/User');

const getAccessTokenSecret = () =>
  process.env.JWT_ACCESS_SECRET ;

const auth = async (req, res, next) => {
  console.log(req.user);
  
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'Token təqdim edilməyib, girişə icazə verilmir' 
      });
    }

    const decoded = jwt.verify(token, getAccessTokenSecret(), {
      algorithms: ["HS256"]
    });

    if (!decoded || !decoded.id) {
      return res.status(401).json({
        success: false,
        message: "Token etibarlı deyil"
      });
    }

    const nowMs = Date.now();
    const expMs = typeof decoded.exp === 'number' ? decoded.exp * 1000 : null;
    const remainingMs = expMs !== null ? expMs - nowMs : null;

    req.auth = {
      token: decoded,
      tokenExpiresAt: expMs,
      tokenExpiresInMs: remainingMs
    };

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

    const currentVersion = typeof user.tokenVersion === 'number' ? user.tokenVersion : 0;

    if (typeof decoded.tokenVersion !== 'number' || decoded.tokenVersion !== currentVersion) {
      return res.status(401).json({
        success: false,
        message: 'Token etibarlı deyil'
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
