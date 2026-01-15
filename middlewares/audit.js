const auditService = require('../services/audit.service');

const auditMiddleware = (req, res, next) => {
  const startedAt = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startedAt;
    const userId = req.user && req.user._id ? req.user._id : null;

    const isAuthRoute = req.originalUrl.startsWith('/api/v1/auth');

    if (!isAuthRoute) {
      auditService.log({
        req,
        userId,
        action: 'request',
        statusCode: res.statusCode,
        metadata: {
          responseTimeMs: duration
        }
      });
    }
  });

  next();
};

module.exports = auditMiddleware;
