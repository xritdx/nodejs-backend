const authService = require("../services/auth.service");
const rbacService = require("../services/rbac.service");
const auditService = require("../services/audit.service");
const User = require("../models/User");

const login = async (req, res, next) => {
  try {
    const {
      user,
      accessToken,
      refreshToken,
      accessTokenExpiresIn,
      refreshTokenExpiresIn,
      accessTokenMaxAgeMs,
      refreshTokenMaxAgeMs,
      rememberMe
    } = await authService.login(req.body);

    if (user.password) delete user.password;

    const statusCode = 200;

    await auditService.log({
      req,
      userId: user._id,
      action: "auth.login",
      statusCode,
      metadata: {
        email: req.body && req.body.email ? req.body.email : null
      }
    });

    res.status(statusCode).json({
      message: "Uğurla daxil oldunuz",
      success: true,
      tokenType: "Bearer",
      user,
      accessToken,
      refreshToken,
      accessTokenExpiresIn,
      refreshTokenExpiresIn,
      accessTokenMaxAgeMs,
      refreshTokenMaxAgeMs,
      rememberMe
    });
  } catch (error) {
    next(error);
  }
};

const refresh = async (req, res, next) => {
  try {
    const refreshTokenFromClient =
      req.body && req.body.refreshToken ? req.body.refreshToken : null;
    if (!refreshTokenFromClient) {
      const error = new Error("Yeniləmə tokeni tapılmadı");
      error.statusCode = 401;
      throw error;
    }

    const {
      userId,
      accessToken,
      refreshToken,
      accessTokenExpiresIn,
      accessTokenMaxAgeMs,
      refreshTokenExpiresIn,
      refreshTokenMaxAgeMs
    } = await authService.refreshAccessToken(refreshTokenFromClient);

    const statusCode = 200;

    await auditService.log({
      req,
      userId,
      action: "auth.refresh",
      statusCode
    });

    res.status(statusCode).json({
      message: "Token uğurla yeniləndi",
      success: true,
      tokenType: "Bearer",
      accessToken,
      refreshToken,
      accessTokenExpiresIn,
      accessTokenMaxAgeMs,
      refreshTokenExpiresIn,
      refreshTokenMaxAgeMs
    });
  } catch (error) {
    next(error);
  }
};

const logout = async (req, res, next) => {
  console.log(req.user);
  
  try {
    const userId = req.user && req.user._id ? req.user._id : null;

    if (!userId) {
      const error = new Error("Sessiya tapılmadı, zəhmət olmasa yenidən daxil olun");
      error.statusCode = 401;
      throw error;
    }

    await authService.logout(userId);

    const statusCode = 200;

    await auditService.log({
      req,
      userId,
      action: "auth.logout",
      statusCode
    });

    res.status(statusCode).json({
      message: "Təhlükəsiz şəkildə çıxış etdiniz",
      success: true
    });
  } catch (error) {
    next(error);
  }
};

const me = async (req, res, next) => {
  try {
    if (!req.user || !req.user._id) {
      return res.status(401).json({
        success: false,
        message: "Sessiya tapılmadı, zəhmət olmasa yenidən daxil olun"
      });
    }

    const user = await User.findById(req.user._id).select("-password");

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "İstifadəçi tapılmadı"
      });
    }

    const roles = await rbacService.getUserRoles(user._id);
    const permissions = await rbacService.getUserPermissions(user._id);

    const tokenExpiresInMs =
      req.auth && typeof req.auth.tokenExpiresInMs === "number"
        ? req.auth.tokenExpiresInMs
        : null;

    res.status(200).json({
      success: true,
      user,
      roles,
      permissions: permissions.map(p => p.slug),
      accessTokenExpiresInMs: tokenExpiresInMs
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  login,
  refresh,
  logout,
  me
};
