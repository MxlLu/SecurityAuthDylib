import { authService } from '../services/auth-service.js';

export const authController = {
  /**
   * POST /api/v1/auth/handshake
   */
  async handleHandshake(req, res) {
    try {
      const { app_bundle_id, client_sdk_version } = req.body;
      const sessionKeyBuffer = req.sessionKeyBuffer;

      const result = await authService.handshake({
        app_bundle_id,
        client_sdk_version,
        sessionKeyBuffer
      });

      // 握手响应使用客户端提供的 sessionKey 进行加密
      return res.sendEncrypted(result, sessionKeyBuffer);
    } catch (err) {
      console.error('[AuthController] 握手处理异常:', err);
      return res.sendError(err.code || 5000, err.msg || err.message || '握手失败');
    }
  },

  /**
   * POST /api/v1/auth/activate
   */
  async handleActivate(req, res) {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = await authService.activate(req.session, req.decryptedBody, clientIp);
      return res.sendEncrypted(result, req.session.sessionKey);
    } catch (err) {
      console.error('[AuthController] 激活处理异常:', err);
      return res.sendError(err.code || 5000, err.msg || err.message || '激活失败');
    }
  },

  /**
   * POST /api/v1/auth/verify
   */
  async handleVerify(req, res) {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = await authService.verify(req.session, req.decryptedBody, clientIp);
      return res.sendEncrypted(result, req.session.sessionKey);
    } catch (err) {
      console.error('[AuthController] 验证处理异常:', err);
      return res.sendError(err.code || 5000, err.msg || err.message || '验证失败');
    }
  },

  /**
   * POST /api/v1/auth/heartbeat
   */
  async handleHeartbeat(req, res) {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const clientTs = req.authContext.clientTimestamp;
      const result = await authService.heartbeat(req.session, req.decryptedBody, clientIp, clientTs);
      return res.sendEncrypted(result, req.session.sessionKey);
    } catch (err) {
      console.error('[AuthController] 心跳处理异常:', err);
      return res.sendError(err.code || 5000, err.msg || err.message || '心跳失败');
    }
  },

  /**
   * POST /api/v1/auth/unbind
   */
  async handleUnbind(req, res) {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = await authService.unbind(req.session, req.decryptedBody, clientIp);
      return res.sendEncrypted(result, req.session.sessionKey);
    } catch (err) {
      console.error('[AuthController] 解绑处理异常:', err);
      return res.sendError(err.code || 5000, err.msg || err.message || '解绑失败');
    }
  }
};
