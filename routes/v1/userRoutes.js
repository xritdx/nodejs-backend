const express = require('express');
const UserController = require('../../controllers/user.controller');
const authMiddleware = require('../../middlewares/auth');
const checkPermission = require('../../middlewares/rbac');

const router = express.Router();

router.get('/get-all', authMiddleware, checkPermission('user.read'), UserController.getAllUsers);

module.exports = router;
