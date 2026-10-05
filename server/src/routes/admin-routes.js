import { Router } from 'express';
import { adminController } from '../controllers/admin-controller.js';

const router = Router();

// 管理员鉴权拦截 (所有管理端 API 均受保护)
router.use(adminController.checkAdminAuth);

// 1. 卡密生成与自定义创建 (单张自定义/批量导入/随机生成)
router.post('/cards/generate', adminController.handleGenerateCards);

// 2. 卡密列表与详情
router.get('/cards/list', adminController.handleListCards);
router.get('/cards/detail/:key', adminController.handleGetCard);

// 3. 卡密状态管理 (FROZEN / ACTIVE)
router.post('/cards/status', adminController.handleUpdateStatus);

// 4. 卡密删除
router.post('/cards/delete', adminController.handleDeleteCard);

// 5. 强制重置/解绑设备
router.post('/cards/reset-bindings', adminController.handleResetBindings);

// 6. 系统业务配置查看与修改
router.get('/config', adminController.handleGetConfig);
router.post('/config/update', adminController.handleUpdateConfig);

// 7. 仪表盘统计与审计日志
router.get('/stats', adminController.handleGetStats);
router.get('/logs', adminController.handleGetLogs);

export default router;
