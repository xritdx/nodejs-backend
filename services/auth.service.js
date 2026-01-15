const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const RoleToUserAssignment = require("../models/RoleToUserAssignment");

const getAccessTokenSecret = () =>
  process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;

const getRefreshTokenSecret = () =>
  process.env.JWT_REFRESH_SECRET || (process.env.JWT_SECRET && process.env.JWT_SECRET + "_refresh");

const ACCESS_TOKEN_EXPIRES_IN = "15m";
const REFRESH_TOKEN_EXPIRES_IN_SHORT = "7d";
const REFRESH_TOKEN_EXPIRES_IN_LONG = "30d";

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

  const accessTokenPayload = {
    id: user._id,
    email: user.email,
    roleId: roleAssignment ? roleAssignment.roleId : null
  };

  const accessToken = jwt.sign(accessTokenPayload, getAccessTokenSecret(), {
    expiresIn: accessTokenExpiresIn
  });

  const refreshToken = jwt.sign(
    { id: user._id },
    getRefreshTokenSecret(),
    { expiresIn: refreshTokenExpiresIn }
  );

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

    const roleAssignment = await RoleToUserAssignment.findOne({ userId: user._id }).select("roleId");

    const accessTokenPayload = {
      id: user._id,
      email: user.email,
      roleId: roleAssignment ? roleAssignment.roleId : null
    };

    const accessToken = jwt.sign(accessTokenPayload, getAccessTokenSecret(), {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN
    });

    return {
      userId: user._id,
      accessToken,
      accessTokenExpiresIn: ACCESS_TOKEN_EXPIRES_IN,
      accessTokenMaxAgeMs: toMs(ACCESS_TOKEN_EXPIRES_IN)
    };
  } catch (err) {
    const error = new Error("Yeniləmə tokeni etibarlı deyil və ya müddəti bitib");
    error.statusCode = 401;
    throw error;
  }
};

module.exports = {
  login,
  refreshAccessToken
};
