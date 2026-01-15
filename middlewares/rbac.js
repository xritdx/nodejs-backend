const rbacService = require('../services/rbac.service');

/**
 * RBAC (Role Based Access Control) Middleware
 * İstifadəçinin tələb olunan icazəyə sahib olub-olmadığını yoxlayır
 * @param {string} permissionSlug - Tələb olunan icazə slug-ı (məs: user.create)
 */
const checkPermission = (permissionSlug) => {
  return async (req, res, next) => {
    try {
      // İstifadəçi login olmayıbsa (auth middleware-dən keçməyibsə)
      if (!req.user || !req.user._id) {
        return res.status(401).json({ 
          message: 'Sessiya tapılmadı, zəhmət olmasa yenidən daxil olun', 
          success: false 
        });
      }

      const hasPerm = await rbacService.hasPermission(req.user._id, permissionSlug);

      if (!hasPerm) {
        return res.status(403).json({ 
          message: 'Bu əməliyyatı yerinə yetirmək üçün kifayət qədər səlahiyyətiniz yoxdur', 
          success: false 
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

module.exports = checkPermission;
