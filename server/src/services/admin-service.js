import crypto from 'node:crypto';
import { cardRepo, bindingRepo, auditRepo } from '../storage/repository.js';
import { config, saveConfig } from '../config/index.js';

function generateRandomKey(prefix = 'PRO', type = 'DAILY') {
  const p1 = type.slice(0, 4);
  const p2 = crypto.randomBytes(2).toString('hex').toUpperCase();
  const p3 = crypto.randomBytes(2).toString('hex').toUpperCase();
  const p4 = crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${prefix}-${p1}-${p2}-${p3}-${p4}`;
}

export const adminService = {
  /**
   * 批量生成或创建自定义卡密
   */
  generateCards({
    count = 1,
    card_type = 'DAILY',
    prefix = 'PRO',
    max_devices = 1,
    max_unbind_limit = 3,
    custom_card_key = null,
    custom_card_keys = null,
    custom_duration_seconds = 0,
    note = ''
  }) {
    const createdCards = [];

    // 1. 如果指定了单个自定义卡密
    if (custom_card_key && typeof custom_card_key === 'string' && custom_card_key.trim().length > 0) {
      const existing = cardRepo.findByKey(custom_card_key);
      if (existing) {
        throw { code: 4000, msg: `自定义卡密已存在: ${custom_card_key}` };
      }
      const card = cardRepo.create({
        card_key: custom_card_key.trim(),
        card_type,
        custom_duration_seconds,
        max_devices,
        max_unbind_limit,
        note
      });
      createdCards.push(card);
      auditRepo.log('ADMIN_CREATE_CUSTOM_CARD', card.card_key, null, null, `创建自定义卡密: ${card.card_key}`);
      return createdCards;
    }

    // 2. 如果指定了多个自定义卡密列表
    if (custom_card_keys && Array.isArray(custom_card_keys) && custom_card_keys.length > 0) {
      for (const k of custom_card_keys) {
        const trimmed = String(k).trim();
        if (!trimmed || cardRepo.findByKey(trimmed)) continue;
        const card = cardRepo.create({
          card_key: trimmed,
          card_type,
          custom_duration_seconds,
          max_devices,
          max_unbind_limit,
          note
        });
        createdCards.push(card);
      }
      auditRepo.log('ADMIN_IMPORT_CUSTOM_CARDS', null, null, null, `批量导入自定义卡密 ${createdCards.length} 张`);
      return createdCards;
    }

    // 3. 随机批量生成
    for (let i = 0; i < count; i++) {
      let cardKey = generateRandomKey(prefix, card_type);
      while (cardRepo.findByKey(cardKey)) {
        cardKey = generateRandomKey(prefix, card_type);
      }
      const card = cardRepo.create({
        card_key: cardKey,
        card_type,
        custom_duration_seconds,
        max_devices,
        max_unbind_limit,
        note
      });
      createdCards.push(card);
    }

    auditRepo.log('ADMIN_GEN_CARDS', null, null, null, `批量生成卡密 ${count} 张，类型: ${card_type}`);
    return createdCards;
  },

  /**
   * 查询所有卡密详情及绑定设备
   */
  listCards() {
    const cards = cardRepo.listAll();
    return cards.map(c => {
      const bindings = bindingRepo.findActiveByCard(c.card_key);
      return {
        ...c,
        active_bindings: bindings
      };
    });
  },

  /**
   * 获取单张卡密详情
   */
  getCard(cardKey) {
    const card = cardRepo.findByKey(cardKey);
    if (!card) throw { code: 4010, msg: '卡密不存在' };
    const bindings = bindingRepo.findActiveByCard(card.card_key);
    return {
      ...card,
      active_bindings: bindings
    };
  },

  /**
   * 冻结或解冻卡密
   */
  updateCardStatus(cardKey, newStatus) {
    const card = cardRepo.findByKey(cardKey);
    if (!card) throw { code: 4010, msg: '卡密不存在' };
    const updated = cardRepo.update(card.card_key, { status: newStatus });
    auditRepo.log('ADMIN_UPDATE_STATUS', card.card_key, null, null, `修改卡密状态为: ${newStatus}`);
    return updated;
  },

  /**
   * 删除卡密
   */
  deleteCard(cardKey) {
    const card = cardRepo.findByKey(cardKey);
    if (!card) throw { code: 4010, msg: '卡密不存在' };
    bindingRepo.unbindAllByCard(card.card_key);
    cardRepo.deleteByKey(card.card_key);
    auditRepo.log('ADMIN_DELETE_CARD', card.card_key, null, null, `删除卡密及解绑所有设备: ${cardKey}`);
    return true;
  },

  /**
   * 管理员强制重置解绑该卡密的所有绑定设备
   */
  resetBindings(cardKey) {
    const card = cardRepo.findByKey(cardKey);
    if (!card) throw { code: 4010, msg: '卡密不存在' };
    const count = bindingRepo.unbindAllByCard(card.card_key);
    auditRepo.log('ADMIN_RESET_BINDINGS', card.card_key, null, null, `强制清空绑定设备: ${count} 台`);
    return { count };
  },

  /**
   * 查看当前业务参数
   */
  getConfig() {
    return {
      service: config.service,
      security: {
        allowed_clock_skew_ms: config.security.allowedClockSkewMs,
        nonce_ttl_sec: config.security.nonceTtlSec,
        heartbeat_interval_sec: config.security.heartbeatIntervalSec,
        heartbeat_lease_timeout_sec: config.security.heartbeatLeaseTimeoutSec,
        default_sign_salt: config.security.defaultSignSalt
      },
      business: config.business
    };
  },

  /**
   * 修改并持久化保存业务参数
   */
  updateConfig(updates) {
    const saved = saveConfig(updates);
    auditRepo.log('ADMIN_UPDATE_CONFIG', null, null, null, '管理员更新业务系统配置');
    return saved;
  },

  /**
   * 统计概览数据
   */
  getStats() {
    const cards = cardRepo.listAll();
    const bindings = bindingRepo.listAllActive();
    const nowSec = Math.floor(Date.now() / 1000);

    let unactivated = 0;
    let active = 0;
    let expired = 0;
    let frozen = 0;

    cards.forEach(c => {
      if (c.status === 'FROZEN') frozen++;
      else if (c.status === 'UNACTIVATED') unactivated++;
      else if (c.status === 'EXPIRED' || (c.expire_at > 0 && nowSec >= c.expire_at)) expired++;
      else if (c.status === 'ACTIVE') active++;
    });

    // 统计在线设备（最近 180 秒内有心跳活跃）
    const onlineDevices = bindings.filter(b => nowSec - b.last_seen_at <= 180).length;

    return {
      total_cards: cards.length,
      unactivated_cards: unactivated,
      active_cards: active,
      expired_cards: expired,
      frozen_cards: frozen,
      total_bound_devices: bindings.length,
      online_devices: onlineDevices,
      heartbeat_interval_sec: config.security.heartbeatIntervalSec
    };
  },

  /**
   * 获取最近审计日志
   */
  getLogs(limit = 100) {
    return auditRepo.listLogs(limit);
  }
};
