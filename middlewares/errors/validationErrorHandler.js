const { validationResult } = require('express-validator');

const validationErrorHandler = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Doğrulama xətası baş verdi',
      errors: errors.array()
    });
  }

  next();
};

module.exports = validationErrorHandler;
