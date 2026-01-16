const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const User = require("../models/User");
const RoleToUserAssignment = require("../models/RoleToUserAssignment");

dotenv.config();

const getAccessTokenSecret = () =>
  process.env.JWT_ACCESS_SECRET ;

const getRefreshTokenSecret = () =>
  process.env.JWT_REFRESH_SECRET ;

const ACCESS_TOKEN_EXPIRES_IN =
  process.env.JWT_ACCESS_EXPIRES_IN || "15m";

const REFRESH_TOKEN_EXPIRES_IN_SHORT =
  process.env.JWT_REFRESH_EXPIRES_IN_SHORT || "7d";

const REFRESH_TOKEN_EXPIRES_IN_LONG =
  process.env.JWT_REFRESH_EXPIRES_IN_LONG || "30d";

const toMs = value => {
  if (typeof value === "number") return value;
  const match = /^(\d+)([smhd])$/.exec(value);
  if (!match) return 0;
  const amount = parseInt(match[1], 10);
  const unit = match[2];
  if (unit === "s") return amount * 1000;
  if (unit === "m") return amount * 60 * 1000;
  if (unit === "h") return amount * 60 * 60 * 1000;
  if (unit === "d") return amount * 24 * 60 * 60 * 1000;
  return 0;
};

const login = async ({ email, password, rememberMe }) => {
  const user = await User.findOne({ email });
  if (!user) {
    const error = new Error("E-mail və ya şifrə yanlışdır");
    error.statusCode = 401;
    throw error;
  }

  if (!user.isActive) {
    const error = new Error("İstifadəçi hesabı deaktiv edilib");
    error.statusCode = 401;
    throw error;
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    const error = new Error("E-mail və ya şifrə yanlışdır");
    error.statusCode = 401;
    throw error;
  }

  const roleAssignment = await RoleToUserAssignment.findOne({ userId: user._id }).select("roleId");

  const accessTokenExpiresIn = ACCESS_TOKEN_EXPIRES_IN;
  const refreshTokenExpiresIn = rememberMe ? REFRESH_TOKEN_EXPIRES_IN_LONG : REFRESH_TOKEN_EXPIRES_IN_SHORT;

  const currentVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
  const nextVersion = currentVersion + 1;
  user.tokenVersion = nextVersion;
  await user.save();

  const accessTokenPayload = {
    id: user._id,
    email: user.email,
    roleId: roleAssignment ? roleAssignment.roleId : null,
    tokenVersion: nextVersion
  };

  const refreshTokenPayload = {
    id: user._id,
    email: user.email,
    tokenVersion: nextVersion,
    rememberMe: !!rememberMe
  };

  const accessToken = jwt.sign(accessTokenPayload, getAccessTokenSecret(), {
    expiresIn: accessTokenExpiresIn
  });

  const refreshToken = jwt.sign(refreshTokenPayload, getRefreshTokenSecret(), {
    expiresIn: refreshTokenExpiresIn
  });

  return {
    user: user.toObject(),
    accessToken,
    refreshToken,
    accessTokenExpiresIn,
    refreshTokenExpiresIn,
    accessTokenMaxAgeMs: toMs(accessTokenExpiresIn),
    refreshTokenMaxAgeMs: toMs(refreshTokenExpiresIn),
    rememberMe: !!rememberMe
  };
};

const refreshAccessToken = async refreshToken => {
  try {
    const decoded = jwt.verify(refreshToken, getRefreshTokenSecret());

    const user = await User.findById(decoded.id);
    if (!user || !user.isActive) {
      const error = new Error("İstifadəçi mövcud deyil və ya deaktiv edilib");
      error.statusCode = 401;
      throw error;
    }

    const currentVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;

    if (typeof decoded.tokenVersion !== "number" || decoded.tokenVersion !== currentVersion) {
      const error = new Error("Yeniləmə tokeni etibarlı deyil və ya müddəti bitib");
      error.statusCode = 401;
      throw error;
    }

    const nextVersion = currentVersion + 1;
    user.tokenVersion = nextVersion;
    await user.save();

    const roleAssignment = await RoleToUserAssignment.findOne({ userId: user._id }).select("roleId");

    const refreshTokenExpiresIn = decoded.rememberMe
      ? REFRESH_TOKEN_EXPIRES_IN_LONG
      : REFRESH_TOKEN_EXPIRES_IN_SHORT;

    const accessTokenPayload = {
      id: user._id,
      email: user.email,
      roleId: roleAssignment ? roleAssignment.roleId : null,
      tokenVersion: nextVersion
    };

    const refreshTokenPayload = {
      id: user._id,
      email: user.email,
      tokenVersion: nextVersion,
      rememberMe: !!decoded.rememberMe
    };

    const accessToken = jwt.sign(accessTokenPayload, getAccessTokenSecret(), {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN
    });

    const newRefreshToken = jwt.sign(refreshTokenPayload, getRefreshTokenSecret(), {
      expiresIn: refreshTokenExpiresIn
    });

    return {
      userId: user._id,
      accessToken,
      refreshToken: newRefreshToken,
      accessTokenExpiresIn: ACCESS_TOKEN_EXPIRES_IN,
      accessTokenMaxAgeMs: toMs(ACCESS_TOKEN_EXPIRES_IN),
      refreshTokenExpiresIn,
      refreshTokenMaxAgeMs: toMs(refreshTokenExpiresIn)
    };
  } catch (err) {
    const error = new Error("Yeniləmə tokeni etibarlı deyil və ya müddəti bitib");
    error.statusCode = 401;
    throw error;
  }
};

const logout = async userId => {
  if (!userId) {
    return;
  }

  const user = await User.findById(userId);
  if (!user) {
    return;
  }

  const currentVersion = typeof user.tokenVersion === "number" ? user.tokenVersion : 0;
  user.tokenVersion = currentVersion + 1;
  await user.save();
};

module.exports = {
  login,
  refreshAccessToken,
  logout
};
