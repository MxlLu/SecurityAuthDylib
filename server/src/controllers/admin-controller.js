import { adminService } from '../services/admin-service.js';
import { config, getAdminApiKey } from '../config/index.js';

export const adminController = {
  checkAdminAuth(req, res, next) {
    const token = req.headers['x-admin-key'] || req.query.key;
    const expectedKey = getAdminApiKey();
    if (!token || token !== expectedKey) {
      return res.status(403).json({ code: 403, msg: '未授权访问管理端 API，请提供合法的 X-Admin-Key' });
    }
    next();
  },

  async handleGenerateCards(req, res) {
    try {
      const {
        count,
        card_type,
        prefix,
        max_devices,
        max_unbind_limit,
        custom_card_key,
        custom_card_keys,
        custom_duration_seconds,
        note
      } = req.body;

      const cards = adminService.generateCards({
        count: count !== undefined ? parseInt(count, 10) : 1,
        card_type: card_type || 'DAILY',
        prefix: prefix || 'PRO',
        max_devices: max_devices !== undefined ? parseInt(max_devices, 10) : 1,
        max_unbind_limit: max_unbind_limit !== undefined ? parseInt(max_unbind_limit, 10) : 3,
        custom_card_key,
        custom_card_keys,
        custom_duration_seconds: custom_duration_seconds ? parseInt(custom_duration_seconds, 10) : 0,
        note
      });
      return res.json({ code: 0, msg: '卡密生成/创建成功', data: cards });
    } catch (err) {
      return res.status(400).json({ code: err.code || 400, msg: err.msg || err.message });
    }
  },

  async handleListCards(req, res) {
    try {
      const cards = adminService.listCards();
      return res.json({ code: 0, msg: 'success', data: cards });
    } catch (err) {
      return res.status(500).json({ code: 500, msg: err.message });
    }
  },

  async handleGetCard(req, res) {
    try {
      const { key } = req.params;
      const card = adminService.getCard(key);
      return res.json({ code: 0, msg: 'success', data: card });
    } catch (err) {
      return res.status(404).json({ code: err.code || 404, msg: err.msg || err.message });
    }
  },

  async handleUpdateStatus(req, res) {
    try {
      const { card_key, status } = req.body;
      const updated = adminService.updateCardStatus(card_key, status);
      return res.json({ code: 0, msg: '状态更新成功', data: updated });
    } catch (err) {
      return res.status(400).json({ code: err.code || 400, msg: err.msg || err.message });
    }
  },

  async handleDeleteCard(req, res) {
    try {
      const { card_key } = req.body;
      adminService.deleteCard(card_key);
      return res.json({ code: 0, msg: `卡密 ${card_key} 已成功删除` });
    } catch (err) {
      return res.status(400).json({ code: err.code || 400, msg: err.msg || err.message });
    }
  },

  async handleResetBindings(req, res) {
    try {
      const { card_key } = req.body;
      const result = adminService.resetBindings(card_key);
      return res.json({ code: 0, msg: `已强制清空该卡密绑定的 ${result.count} 台设备` });
    } catch (err) {
      return res.status(400).json({ code: err.code || 400, msg: err.msg || err.message });
    }
  },

  async handleGetConfig(req, res) {
    try {
      const currentConfig = adminService.getConfig();
      return res.json({ code: 0, msg: 'success', data: currentConfig });
    } catch (err) {
      return res.status(500).json({ code: 500, msg: err.message });
    }
  },

  async handleUpdateConfig(req, res) {
    try {
      const updates = req.body;
      const newConfig = adminService.updateConfig(updates);
      return res.json({ code: 0, msg: '业务参数更新成功', data: newConfig });
    } catch (err) {
      return res.status(500).json({ code: 500, msg: err.message });
    }
  },

  async handleGetStats(req, res) {
    try {
      const stats = adminService.getStats();
      return res.json({ code: 0, msg: 'success', data: stats });
    } catch (err) {
      return res.status(500).json({ code: 500, msg: err.message });
    }
  },

  async handleGetLogs(req, res) {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit, 10) : 100;
      const logs = adminService.getLogs(limit);
      return res.json({ code: 0, msg: 'success', data: logs });
    } catch (err) {
      return res.status(500).json({ code: 500, msg: err.message });
    }
  }
};
