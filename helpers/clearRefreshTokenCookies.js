const isProd = process.env.NODE_ENV === "production";

const clearRefreshTokenCookies = res => {
  const common = {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax"
  };

  res.clearCookie("refreshToken", { ...common, path: "/api/v1" });
  res.clearCookie("refreshToken", { ...common, path: "/" });
};


const buildRefreshCookieOptions = (maxAge) => {
  const options = {
    httpOnly: true,
    secure: isProd,                     // prod: true, dev: false
    sameSite: isProd ? "none" : "lax",  // cross-site prod, dev-də HTTP uyumlu
    path: "/",                          // ❗ path "/" olaraq dəyişdirildi ki, bütün sorğularda əlçatan olsun
  };

  if (typeof maxAge === "number") {
    options.maxAge = maxAge;
  }

  return options;
};


module.exports = {
  clearRefreshTokenCookies,
  buildRefreshCookieOptions
};
