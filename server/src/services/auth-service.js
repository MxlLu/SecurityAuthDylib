import crypto from 'node:crypto';
import { cardRepo, bindingRepo, sessionRepo, auditRepo } from '../storage/repository.js';
import { verifyChallengeResponse } from '../crypto/signature.js';
import { config } from '../config/index.js';

function computeDeviceHash(fp) {
  if (!fp) return 'unknown_device';
  const raw = `${fp.keychain_uuid || ''}|${fp.hardware_hash || ''}|${fp.device_model || ''}`;
  return crypto.createHash('sha256').update(raw, 'utf-8').digest('hex');
}

function calculateExpirySeconds(card) {
  if (card.custom_duration_seconds && card.custom_duration_seconds > 0) {
    return card.custom_duration_seconds;
  }
  const durations = config.business.cardDurations || {};
  if (card.card_type && durations[card.card_type] !== undefined) {
    return durations[card.card_type];
  }
  return 86400;
}

export const authService = {
  /**
   * 1. 握手与时钟对齐
   */
  async handshake({ app_bundle_id, client_sdk_version, sessionKeyBuffer }) {
    // 检查宿主 Bundle ID 白名单限制
    const whitelist = config.service.bundleIdWhitelist;
    if (whitelist && Array.isArray(whitelist) && whitelist.length > 0) {
      if (!app_bundle_id || !whitelist.includes(app_bundle_id)) {
        throw { code: 4020, msg: `应用 Bundle ID 未授权接入: ${app_bundle_id}` };
      }
    }

    const clientId = `cli_${crypto.randomBytes(8).toString('hex')}`;
    const signSalt = crypto.randomBytes(16).toString('hex');

    // 在仓储中记录客户端会话
    sessionRepo.createClientSession(clientId, sessionKeyBuffer, signSalt);

    auditRepo.log('HANDSHAKE', null, null, { app_bundle_id, client_sdk_version }, `客户端握手分配 ID: ${clientId}`);

    return {
      client_id: clientId,
      server_timestamp: Date.now(),
      heartbeat_interval_sec: config.security.heartbeatIntervalSec,
      sign_salt: signSalt
    };
  },

  /**
   * 2. 卡密激活与绑定
   */
  async activate(session, { card_key, device_fingerprint }, clientIp) {
    if (!card_key || !device_fingerprint) {
      throw { code: 4000, msg: '缺少卡密或设备指纹数据' };
    }

    const card = cardRepo.findByKey(card_key);
    if (!card) {
      throw { code: 4010, msg: '卡密不存在，请检查后重试' };
    }

    if (card.status === 'FROZEN') {
      throw { code: 4012, msg: '卡密已被管理员冻结' };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (card.status === 'EXPIRED' || (card.expire_at > 0 && nowSec >= card.expire_at)) {
      cardRepo.update(card.card_key, { status: 'EXPIRED' });
      throw { code: 4011, msg: '卡密已过期' };
    }

    const deviceFpHash = computeDeviceHash(device_fingerprint);
    const activeBindings = bindingRepo.findActiveByCard(card.card_key);
    const existingBinding = activeBindings.find(b => b.device_fp_hash === deviceFpHash);

    if (!existingBinding) {
      if (activeBindings.length >= card.max_devices) {
        throw { code: 4013, msg: `设备绑定数量已达上限 (最大允许: ${card.max_devices})` };
      }
      // 记录新设备绑定
      bindingRepo.create({
        card_key: card.card_key,
        device_fp_hash: deviceFpHash,
        keychain_uuid: device_fingerprint.keychain_uuid || '',
        device_model: device_fingerprint.device_model || '',
        system_version: device_fingerprint.system_version || '',
        last_ip: clientIp
      });
    } else {
      bindingRepo.updateLastSeen(card.card_key, deviceFpHash, clientIp);
    }

    // 若首次激活，初始化卡密到期时间
    if (card.status === 'UNACTIVATED') {
      const durationSec = calculateExpirySeconds(card);
      const expireAt = durationSec === 0 ? 0 : nowSec + durationSec;
      cardRepo.update(card.card_key, {
        status: 'ACTIVE',
        activated_at: nowSec,
        expire_at: expireAt
      });
      card.status = 'ACTIVE';
      card.activated_at = nowSec;
      card.expire_at = expireAt;
    }

    // 签发会话凭据与初始挑战码
    const sessionToken = `sess_${crypto.randomUUID().replace(/-/g, '')}`;
    const challengeToken = `chall_${crypto.randomBytes(8).toString('hex')}`;

    sessionRepo.bindTokenToSession(session.clientId, sessionToken, card.card_key, challengeToken);

    auditRepo.log('ACTIVATE', card.card_key, clientIp, device_fingerprint, `激活成功，设备哈希: ${deviceFpHash.slice(0, 10)}...`);

    const currentBindingsCount = bindingRepo.findActiveByCard(card.card_key).length;

    return {
      card_key: card.card_key,
      card_type: card.card_type,
      status: card.status,
      activated_at: card.activated_at,
      expire_at: card.expire_at,
      session_token: sessionToken,
      challenge_token: challengeToken,
      max_devices: card.max_devices,
      bound_devices_count: currentBindingsCount
    };
  },

  /**
   * 3. 登录核验 (冷启动静默登录)
   */
  async verify(session, { card_key, session_token, device_fingerprint }, clientIp) {
    const card = cardRepo.findByKey(card_key);
    if (!card) {
      throw { code: 4010, msg: '卡密不存在' };
    }

    if (card.status === 'FROZEN') {
      throw { code: 4012, msg: '卡密已被冻结' };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (card.status === 'EXPIRED' || (card.expire_at > 0 && nowSec >= card.expire_at)) {
      throw { code: 4011, msg: '卡密已过期' };
    }

    const deviceFpHash = computeDeviceHash(device_fingerprint);
    const binding = bindingRepo.findBinding(card.card_key, deviceFpHash);
    if (!binding) {
      throw { code: 4014, msg: '当前设备未绑定该卡密，请先激活或换绑' };
    }

    bindingRepo.updateLastSeen(card.card_key, deviceFpHash, clientIp);

    const nextChallenge = `chall_${crypto.randomBytes(8).toString('hex')}`;
    const token = session_token || `sess_${crypto.randomUUID().replace(/-/g, '')}`;
    sessionRepo.bindTokenToSession(session.clientId, token, card.card_key, nextChallenge);

    const remainingSeconds = card.expire_at === 0 ? 999999999 : Math.max(0, card.expire_at - nowSec);

    auditRepo.log('VERIFY', card.card_key, clientIp, device_fingerprint, '免密静默登录成功');

    return {
      valid: true,
      card_key: card.card_key,
      expire_at: card.expire_at,
      remaining_seconds: remainingSeconds,
      challenge_token: nextChallenge,
      session_token: token,
      announcement: config.business.announcement
    };
  },

  /**
   * 4. 动态心跳续租
   */
  async heartbeat(session, { session_token, challenge_response, uptime_sec, tamper_status }, clientIp, clientTimestamp) {
    if (!session_token) {
      throw { code: 4004, msg: '缺少会话令牌 (session_token)' };
    }

    // 1. 检查会话与上一轮挑战码
    if (!session.currentChallenge) {
      throw { code: 4016, msg: '会话挑战凭据丢失，请重新验证' };
    }

    // 2. 校验滚动挑战应答
    const isChallengeValid = verifyChallengeResponse(
      session.currentChallenge,
      session.signSalt,
      clientTimestamp,
      challenge_response
    );

    if (!isChallengeValid) {
      auditRepo.log('TAMPER', session.cardKey, clientIp, tamper_status, '心跳挑战码核验失败！可能存在内存伪造或重放');
      throw { code: 4016, msg: '心跳滚动挑战码核验失败' };
    }

    // 3. 检查卡密有效性
    const card = cardRepo.findByKey(session.cardKey);
    if (!card || card.status === 'FROZEN') {
      throw { code: 4012, msg: '卡密已失效或被冻结' };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (card.expire_at > 0 && nowSec >= card.expire_at) {
      cardRepo.update(card.card_key, { status: 'EXPIRED' });
      throw { code: 4011, msg: '卡密在运行中心跳检测到已到期' };
    }

    // 4. 下发新挑战码并更新租约
    const nextChallenge = `chall_${crypto.randomBytes(8).toString('hex')}`;
    sessionRepo.updateChallenge(session_token, nextChallenge);

    return {
      alive: true,
      next_challenge_token: nextChallenge,
      expire_at: card.expire_at,
      force_action: 'NONE'
    };
  },

  /**
   * 5. 设备解绑申请
   */
  async unbind(session, { card_key, device_fingerprint, reason }, clientIp) {
    const card = cardRepo.findByKey(card_key);
    if (!card) {
      throw { code: 4010, msg: '卡密不存在' };
    }

    if (card.unbind_count >= card.max_unbind_limit) {
      throw { code: 4015, msg: `解绑次数已达上限 (已用: ${card.unbind_count}/${card.max_unbind_limit})` };
    }

    const deviceFpHash = computeDeviceHash(device_fingerprint);
    const unbindOk = bindingRepo.unbind(card.card_key, deviceFpHash);
    if (!unbindOk) {
      throw { code: 4014, msg: '未找到该设备的绑定记录或已被解绑' };
    }

    // 执行惩罚时长扣除（从配置读取，永久卡除外）
    const deductHours = config.business.unbindDeductHours ?? 2;
    let newExpireAt = card.expire_at;
    if (card.expire_at > 0) {
      newExpireAt = Math.max(Math.floor(Date.now() / 1000), card.expire_at - deductHours * 3600);
    }

    const newUnbindCount = card.unbind_count + 1;
    cardRepo.update(card.card_key, {
      unbind_count: newUnbindCount,
      expire_at: newExpireAt
    });

    auditRepo.log('UNBIND', card.card_key, clientIp, device_fingerprint, `设备解绑成功，原因: ${reason || '无'}`);

    return {
      unbind_success: true,
      unbind_count_used: newUnbindCount,
      unbind_count_limit: card.max_unbind_limit,
      deducted_hours: deductHours,
      new_expire_at: newExpireAt
    };
  }
};
