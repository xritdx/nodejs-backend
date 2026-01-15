const authService = require("../services/auth.service");
const rbacService = require("../services/rbac.service");
const auditService = require("../services/audit.service");
const User = require("../models/User");

const getCookieOptions = maxAge => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge,
  path: "/api/v1/auth"
});

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

    res.cookie("refreshToken", refreshToken, getCookieOptions(refreshTokenMaxAgeMs));

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
      accessTokenExpiresIn,
      refreshTokenExpiresIn,
      accessTokenMaxAgeMs,
      rememberMe
    });
  } catch (error) {
    next(error);
  }
};

const refresh = async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) {
      const error = new Error("Yeniləmə tokeni tapılmadı");
      error.statusCode = 401;
      throw error;
    }

    const {
      userId,
      accessToken,
      accessTokenExpiresIn,
      accessTokenMaxAgeMs
    } = await authService.refreshAccessToken(refreshToken);

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
      accessTokenExpiresIn,
      accessTokenMaxAgeMs
    });
  } catch (error) {
    next(error);
  }
};

const logout = async (req, res, next) => {
  try {
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/api/v1/auth"
    });

    const statusCode = 200;

    await auditService.log({
      req,
      userId: req.user && req.user._id ? req.user._id : null,
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

    res.status(200).json({
      success: true,
      user,
      roles,
      permissions: permissions.map(p => p.slug)
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
