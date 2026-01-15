const express = require('express');
const AuthController = require('../../controllers/auth.controller');
const { loginValidation } = require('../../validations/login.validation');
const validationErrorHandler = require('../../middlewares/errors/validationErrorHandler');
const authMiddleware = require('../../middlewares/auth');

const router = express.Router();

router.post('/login', loginValidation, validationErrorHandler, AuthController.login);
router.post('/refresh', AuthController.refresh);
router.post('/logout', authMiddleware, AuthController.logout);
router.get('/me', authMiddleware, AuthController.me);

module.exports = router;
