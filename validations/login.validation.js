const { body } = require('express-validator');

const loginValidation = [
  body('email')
    .isEmail()
    .withMessage('Zəhmət olmasa düzgün e-poçt ünvanı daxil edin')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Şifrə ən azı 8 simvoldan ibarət olmalıdır')
    .bail(),
  body('rememberMe')
    .optional()
    .isBoolean()
    .withMessage('rememberMe dəyəri boolean olmalıdır')
    .toBoolean()
];

module.exports = {
  loginValidation
};
