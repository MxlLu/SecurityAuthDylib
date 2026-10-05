import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const serverDir = path.resolve(__dirname, '../..');
const configJsonPath = path.join(serverDir, 'config.json');

// 加载外部 JSON 配置文件
let rawJsonConfig = {};
if (fs.existsSync(configJsonPath)) {
  try {
    rawJsonConfig = JSON.parse(fs.readFileSync(configJsonPath, 'utf-8'));
  } catch (err) {
    console.error('[Config] 读取 config.json 失败，将使用默认参数:', err.message);
  }
}

export function getAdminApiKey() {
  if (process.env.ADMIN_API_KEY) return process.env.ADMIN_API_KEY;
  try {
    if (fs.existsSync(configJsonPath)) {
      const latest = JSON.parse(fs.readFileSync(configJsonPath, 'utf-8'));
      if (latest.service?.admin_api_key) {
        return latest.service.admin_api_key;
      }
    }
  } catch (err) {}
  return config.security?.adminApiKey || 'admin_secret_token_123456';
}

export const config = {
  port: parseInt(process.env.PORT || rawJsonConfig.service?.port || '4090', 10),
  host: process.env.HOST || '0.0.0.0',
  env: process.env.NODE_ENV || 'development',
  
  // 业务基础参数
  service: {
    appName: rawJsonConfig.service?.app_name || 'iOS Security License System',
    bundleIdWhitelist: rawJsonConfig.service?.bundle_id_whitelist || [],
    adminApiKey: process.env.ADMIN_API_KEY || rawJsonConfig.service?.admin_api_key || 'admin_secret_token_123456'
  },

  // 安全与防重放参数
  security: {
    allowedClockSkewMs: rawJsonConfig.security?.allowed_clock_skew_ms ?? 30000,
    nonceTtlSec: rawJsonConfig.security?.nonce_ttl_sec ?? 60,
    heartbeatIntervalSec: rawJsonConfig.security?.heartbeat_interval_sec ?? 60,
    heartbeatLeaseTimeoutSec: rawJsonConfig.security?.heartbeat_lease_timeout_sec ?? 180,
    defaultSignSalt: process.env.DEFAULT_SIGN_SALT || rawJsonConfig.security?.default_sign_salt || 'salt_ios_auth_v1_secure_2026',
    adminApiKey: process.env.ADMIN_API_KEY || rawJsonConfig.service?.admin_api_key || 'admin_secret_token_123456'
  },

  // 业务策略参数
  business: {
    unbindDeductHours: rawJsonConfig.business?.unbind_deduct_hours ?? 2,
    defaultMaxUnbindLimit: rawJsonConfig.business?.default_max_unbind_limit ?? 3,
    announcement: rawJsonConfig.business?.announcement || {
      id: 1,
      title: '系统通知',
      content: 'iOS 授权系统运行正常',
      force_alert: false
    },
    cardDurations: rawJsonConfig.business?.card_durations || {
      TRIAL_1H: 3600,
      DAILY: 86400,
      WEEKLY: 604800,
      MONTHLY: 2592000,
      QUARTERLY: 7776000,
      ANNUAL: 31536000,
      LIFETIME: 0
    }
  },

  // 路径配置
  paths: {
    serverDir,
    configJsonPath,
    keysDir: path.join(serverDir, 'keys'),
    dataDir: path.join(serverDir, 'data'),
    publicKeyPath: path.join(serverDir, 'keys', 'server_public.pem'),
    privateKeyPath: path.join(serverDir, 'keys', 'server_private.pem'),
    storageFilePath: path.join(serverDir, 'data', 'auth_store.json')
  }
};

/**
 * 动态更新并保存配置到 config.json
 */
export function saveConfig(updates) {
  if (updates.service) Object.assign(config.service, updates.service);
  if (updates.security) Object.assign(config.security, updates.security);
  if (updates.business) Object.assign(config.business, updates.business);

  const exported = {
    service: {
      app_name: config.service.appName,
      bundle_id_whitelist: config.service.bundleIdWhitelist,
      admin_api_key: config.service.adminApiKey
    },
    security: {
      allowed_clock_skew_ms: config.security.allowedClockSkewMs,
      nonce_ttl_sec: config.security.nonceTtlSec,
      heartbeat_interval_sec: config.security.heartbeatIntervalSec,
      heartbeat_lease_timeout_sec: config.security.heartbeatLeaseTimeoutSec,
      default_sign_salt: config.security.defaultSignSalt
    },
    business: {
      unbind_deduct_hours: config.business.unbindDeductHours,
      default_max_unbind_limit: config.business.defaultMaxUnbindLimit,
      announcement: config.business.announcement,
      card_durations: config.business.cardDurations
    }
  };

  fs.writeFileSync(config.paths.configJsonPath, JSON.stringify(exported, null, 2), 'utf-8');
  return exported;
}
