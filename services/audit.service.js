const AuditLog = require('../models/AuditLog');

const resolveIp = req => {
  const headerIp = req.headers['x-forwarded-for'];
  if (typeof headerIp === 'string') {
    const parts = headerIp.split(',');
    if (parts.length > 0) return parts[0].trim();
  }
  return req.ip;
};

const log = async ({
  req,
  userId = null,
  action,
  statusCode,
  metadata = {}
}) => {
  try {
    await AuditLog.create({
      userId,
      action,
      method: req.method,
      path: req.originalUrl,
      ip: resolveIp(req),
      userAgent: req.headers['user-agent'],
      statusCode,
      metadata
    });
  } catch (err) {
    console.error('Audit log xətası:', err.message);
  }
};

module.exports = {
  log
};

