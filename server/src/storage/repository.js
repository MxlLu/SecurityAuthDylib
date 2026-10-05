import crypto from 'node:crypto';
import { getStore, persist } from './json-store.js';
import { config } from '../config/index.js';

// ==========================================
// 1. Nonce 防重放池 (内存存储，定时淘汰)
// ==========================================
class NonceManager {
  constructor() {
    this.nonces = new Map(); // nonce -> expireTimestampMs
    // 每 30 秒清理一次过期 Nonce
    setInterval(() => this.cleanup(), 30000).unref();
  }

  checkAndStore(nonce, ttlSec = config.security.nonceTtlSec) {
    const now = Date.now();
    if (this.nonces.has(nonce)) {
      const exp = this.nonces.get(nonce);
      if (now < exp) {
        return false; // 重复 Nonce，触发重放警报
      }
    }
    this.nonces.set(nonce, now + ttlSec * 1000);
    return true;
  }

  cleanup() {
    const now = Date.now();
    for (const [nonce, exp] of this.nonces.entries()) {
      if (now >= exp) {
        this.nonces.delete(nonce);
      }
    }
  }
}

export const nonceRepo = new NonceManager();

// ==========================================
// 2. 客户端会话 Session 管理器
// ==========================================
class SessionManager {
  constructor() {
    // client_id -> SessionData
    // session_token -> client_id
    this.clientSessions = new Map();
    this.tokenToClientId = new Map();
  }

  createClientSession(clientId, sessionKeyBuffer, signSalt) {
    const sessionData = {
      clientId,
      sessionKey: sessionKeyBuffer, // 32 字节 Buffer
      signSalt: signSalt || crypto.randomBytes(16).toString('hex'),
      sessionToken: null,
      cardKey: null,
      currentChallenge: null,
      lastHeartbeatAt: Date.now(),
      createdAt: Date.now()
    };
    this.clientSessions.set(clientId, sessionData);
    return sessionData;
  }

  getSessionByClientId(clientId) {
    return this.clientSessions.get(clientId) || null;
  }

  getSessionByToken(sessionToken) {
    if (!sessionToken) return null;
    const clientId = this.tokenToClientId.get(sessionToken);
    if (!clientId) return null;
    return this.clientSessions.get(clientId) || null;
  }

  bindTokenToSession(clientId, sessionToken, cardKey, initialChallenge) {
    const sess = this.clientSessions.get(clientId);
    if (!sess) return false;
    sess.sessionToken = sessionToken;
    sess.cardKey = cardKey;
    sess.currentChallenge = initialChallenge;
    sess.lastHeartbeatAt = Date.now();
    this.tokenToClientId.set(sessionToken, clientId);
    return true;
  }

  updateChallenge(sessionToken, nextChallenge) {
    const sess = this.getSessionByToken(sessionToken);
    if (sess) {
      sess.currentChallenge = nextChallenge;
      sess.lastHeartbeatAt = Date.now();
      return true;
    }
    return false;
  }

  destroySession(sessionToken) {
    const sess = this.getSessionByToken(sessionToken);
    if (sess) {
      this.tokenToClientId.delete(sessionToken);
      this.clientSessions.delete(sess.clientId);
    }
  }
}

export const sessionRepo = new SessionManager();

// ==========================================
// 3. 卡密数据仓储 (CardRepository)
// ==========================================
export const cardRepo = {
  findByKey(cardKey) {
    if (!cardKey) return null;
    const store = getStore();
    return store.cards.find(c => c.card_key.toUpperCase() === cardKey.trim().toUpperCase()) || null;
  },

  create(card) {
    const store = getStore();
    const newCard = {
      id: Date.now() + Math.floor(Math.random() * 1000),
      card_key: card.card_key.toUpperCase(),
      card_type: card.card_type || 'DAILY',
      custom_duration_seconds: card.custom_duration_seconds || 0,
      status: card.status || 'UNACTIVATED',
      max_devices: card.max_devices || 1,
      unbind_count: 0,
      max_unbind_limit: card.max_unbind_limit ?? 3,
      activated_at: 0,
      expire_at: card.expire_at || 0,
      note: card.note || '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    store.cards.push(newCard);
    persist();
    return newCard;
  },

  deleteByKey(cardKey) {
    if (!cardKey) return false;
    const store = getStore();
    const idx = store.cards.findIndex(c => c.card_key.toUpperCase() === cardKey.trim().toUpperCase());
    if (idx !== -1) {
      store.cards.splice(idx, 1);
      persist();
      return true;
    }
    return false;
  },

  update(cardKey, updates) {
    const card = this.findByKey(cardKey);
    if (!card) return null;
    Object.assign(card, updates, { updated_at: new Date().toISOString() });
    persist();
    return card;
  },

  listAll() {
    return getStore().cards;
  }
};

// ==========================================
// 4. 设备绑定仓储 (BindingRepository)
// ==========================================
export const bindingRepo = {
  findActiveByCard(cardKey) {
    const store = getStore();
    return store.bindings.filter(b => b.card_key === cardKey && b.is_active === 1);
  },

  findBinding(cardKey, deviceFpHash) {
    const store = getStore();
    return store.bindings.find(b => b.card_key === cardKey && b.device_fp_hash === deviceFpHash && b.is_active === 1) || null;
  },

  create(binding) {
    const store = getStore();
    const item = {
      id: Date.now() + Math.floor(Math.random() * 1000),
      card_key: binding.card_key,
      device_fp_hash: binding.device_fp_hash,
      keychain_uuid: binding.keychain_uuid,
      device_model: binding.device_model || '',
      system_version: binding.system_version || '',
      first_bound_at: Math.floor(Date.now() / 1000),
      last_seen_at: Math.floor(Date.now() / 1000),
      last_ip: binding.last_ip || '',
      is_active: 1
    };
    store.bindings.push(item);
    persist();
    return item;
  },

  unbind(cardKey, deviceFpHash) {
    const binding = this.findBinding(cardKey, deviceFpHash);
    if (binding) {
      binding.is_active = 0;
      binding.unbound_at = Math.floor(Date.now() / 1000);
      persist();
      return true;
    }
    return false;
  },

  unbindAllByCard(cardKey) {
    const store = getStore();
    let count = 0;
    store.bindings.forEach(b => {
      if (b.card_key === cardKey && b.is_active === 1) {
        b.is_active = 0;
        b.unbound_at = Math.floor(Date.now() / 1000);
        count++;
      }
    });
    if (count > 0) persist();
    return count;
  },

  updateLastSeen(cardKey, deviceFpHash, ip) {
    const binding = this.findBinding(cardKey, deviceFpHash);
    if (binding) {
      binding.last_seen_at = Math.floor(Date.now() / 1000);
      if (ip) binding.last_ip = ip;
      persist();
    }
  },

  listAllActive() {
    const store = getStore();
    return store.bindings.filter(b => b.is_active === 1);
  }
};

// ==========================================
// 5. 审计日志仓储 (AuditLogRepository)
// ==========================================
export const auditRepo = {
  log(actionType, cardKey, clientIp, deviceInfo, payloadSummary) {
    const store = getStore();
    const item = {
      id: Date.now() + Math.floor(Math.random() * 1000),
      action_type: actionType,
      card_key: cardKey || '',
      client_ip: clientIp || '',
      device_info: typeof deviceInfo === 'object' ? JSON.stringify(deviceInfo) : String(deviceInfo || ''),
      payload_summary: payloadSummary || '',
      created_at: new Date().toISOString()
    };
    store.audit_logs.push(item);
    // 控制日志保留最近 1000 条
    if (store.audit_logs.length > 1000) {
      store.audit_logs.splice(0, store.audit_logs.length - 1000);
    }
    persist();
    return item;
  },

  listLogs(limit = 100) {
    const store = getStore();
    return [...store.audit_logs].reverse().slice(0, limit);
  }
};
