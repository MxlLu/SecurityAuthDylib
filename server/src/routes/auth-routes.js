import { Router } from 'express';
import { authController } from '../controllers/auth-controller.js';
import { replayDefense, handshakeSecurity, businessSecurity } from '../middleware/security.js';

const router = Router();

// 1. 握手与时钟对齐
router.post('/handshake', replayDefense, handshakeSecurity, authController.handleHandshake);

// 2. 卡密激活与绑定
router.post('/activate', replayDefense, businessSecurity, authController.handleActivate);

// 3. 登录核验 (静默登录)
router.post('/verify', replayDefense, businessSecurity, authController.handleVerify);

// 4. 动态心跳续租
router.post('/heartbeat', replayDefense, businessSecurity, authController.handleHeartbeat);

// 5. 设备解绑申请
router.post('/unbind', replayDefense, businessSecurity, authController.handleUnbind);

export default router;
