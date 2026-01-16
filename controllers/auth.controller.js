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

    const roles = await rbacService.getUserRoles(user._id);
    const permissions = await rbacService.getUserPermissions(user._id);

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

    const cookieOptions = {
      httpOnly: true,
      secure: "production",
      sameSite: "none",
      maxAge: refreshTokenMaxAgeMs
    };

    res.cookie("refreshToken", refreshToken, cookieOptions);

    res.status(statusCode).json({
      message: "Uğurla daxil oldunuz",
      success: true,
      tokenType: "Bearer",
      user,
      roles,
      permissions: permissions.map(p => p.slug),
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
    const refreshTokenFromClient =
      req.cookies && req.cookies.refreshToken ? req.cookies.refreshToken : null;
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

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: refreshTokenMaxAgeMs
    };

    res.cookie("refreshToken", refreshToken, cookieOptions);

    res.status(statusCode).json({
      message: "Token uğurla yeniləndi",
      success: true,
      tokenType: "Bearer",
      accessToken,
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

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict"
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
      message: "Sessiya məlumatları uğurla gətirildi",
      success: true,
      tokenType: "Bearer",
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
