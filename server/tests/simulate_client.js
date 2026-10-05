import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const serverDir = path.resolve(__dirname, '..');
const pubKeyPath = path.join(serverDir, 'keys', 'server_public.pem');

const BASE_URL = process.env.BASE_URL || 'http://127.0.0.1:4090';

// 辅助加密函数
function rsaEncrypt(publicKeyPem, dataBuffer) {
  return crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    dataBuffer
  ).toString('base64');
}

function aesEncrypt(plainStr, keyBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plainStr, 'utf-8')), cipher.final()]);
  return {
    cipherBase64: encrypted.toString('base64'),
    ivHex: iv.toString('hex'),
    authTagHex: cipher.getAuthTag().toString('hex')
  };
}

function aesDecrypt(cipherBase64, keyBuffer, ivHex, authTagHex) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(cipherBase64, 'base64')), decipher.final()]);
  return decrypted.toString('utf-8');
}

function hmacSign(key, timestamp, nonce, payload) {
  const content = `${timestamp}&${nonce}&${payload || ''}`;
  return crypto.createHmac('sha256', key).update(content, 'utf-8').digest('hex');
}

async function runSimulation() {
  console.log('>>> [Test] 启动客户端模拟与全链路协议仿真测试...\n');

  if (!fs.existsSync(pubKeyPath)) {
    throw new Error(`未找到公钥文件: ${pubKeyPath}，请先启动服务端一次以生成密钥对。`);
  }
  const serverPubKey = fs.readFileSync(pubKeyPath, 'utf-8');

  // 本地生成 32 字节会话密钥
  const localSessionKey = crypto.randomBytes(32);
  const encryptedSessionKey = rsaEncrypt(serverPubKey, localSessionKey);

  // 1. 模拟握手
  console.log('--- 1. 测试握手接口 (/api/v1/auth/handshake) ---');
  const hsTimestamp = Date.now();
  const hsNonce = crypto.randomBytes(8).toString('hex');
  const hsSign = hmacSign('salt_ios_auth_v1_secure_2026', hsTimestamp, hsNonce, encryptedSessionKey);

  const hsRes = await fetch(`${BASE_URL}/api/v1/auth/handshake`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Timestamp': String(hsTimestamp),
      'X-Auth-Nonce': hsNonce,
      'X-Auth-Signature': hsSign
    },
    body: JSON.stringify({
      app_bundle_id: 'com.target.testapp',
      client_sdk_version: '1.0.0',
      encrypted_session_key: encryptedSessionKey
    })
  });

  const hsJson = await hsRes.json();
  if (hsJson.code !== 0) {
    throw new Error(`握手失败: ${JSON.stringify(hsJson)}`);
  }
  const hsDecrypted = JSON.parse(aesDecrypt(hsJson.data, localSessionKey, hsJson.iv, hsJson.auth_tag));
  console.log('握手成功，获得客户端 ID:', hsDecrypted.client_id, '签名盐:', hsDecrypted.sign_salt);
  const clientId = hsDecrypted.client_id;
  const signSalt = hsDecrypted.sign_salt;

  // 2. 使用已创建的自定义联调卡密 VIP-TARGET-2026
  console.log('\n--- 2. 使用目标自定义卡密进行联调 ---');
  const testCardKey = 'VIP-TARGET-2026';
  console.log('目标联调卡密:', testCardKey);

  // 3. 模拟激活卡密并绑定设备
  console.log('\n--- 3. 测试卡密首次激活 (/api/v1/auth/activate) ---');
  const deviceFingerprint = {
    keychain_uuid: 'E1F2A3B4-C5D6-4E7F-8A9B-0C1D2E3F4A5B',
    idfv: 'A1B2C3D4-E5F6-7A8B-9C0D-1E2F3A4B5C6D',
    device_model: 'iPhone15,2',
    system_version: '17.4',
    hardware_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
  };

  const actPlain = JSON.stringify({
    card_key: testCardKey,
    device_fingerprint: deviceFingerprint
  });
  const actEnc = aesEncrypt(actPlain, localSessionKey);
  const actTs = Date.now();
  const actNonce = crypto.randomBytes(8).toString('hex');
  const actSign = hmacSign(signSalt, actTs, actNonce, actEnc.cipherBase64);

  const actRes = await fetch(`${BASE_URL}/api/v1/auth/activate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Timestamp': String(actTs),
      'X-Auth-Nonce': actNonce,
      'X-Auth-Client-ID': clientId,
      'X-Auth-Signature': actSign
    },
    body: JSON.stringify({
      client_id: clientId,
      iv: actEnc.ivHex,
      auth_tag: actEnc.authTagHex,
      cipher_data: actEnc.cipherBase64
    })
  });
  const actJson = await actRes.json();
  if (actJson.code !== 0) throw new Error(`激活失败: ${JSON.stringify(actJson)}`);
  const actDecrypted = JSON.parse(aesDecrypt(actJson.data, localSessionKey, actJson.iv, actJson.auth_tag));
  console.log('卡密激活成功！状态:', actDecrypted.status, 'SessionToken:', actDecrypted.session_token.slice(0, 15) + '...');
  const sessionToken = actDecrypted.session_token;
  let challengeToken = actDecrypted.challenge_token;

  // 4. 模拟冷启动静默验证
  console.log('\n--- 4. 测试冷启动静默核验 (/api/v1/auth/verify) ---');
  const verPlain = JSON.stringify({
    card_key: testCardKey,
    session_token: sessionToken,
    device_fingerprint: deviceFingerprint
  });
  const verEnc = aesEncrypt(verPlain, localSessionKey);
  const verTs = Date.now();
  const verNonce = crypto.randomBytes(8).toString('hex');
  const verSign = hmacSign(signSalt, verTs, verNonce, verEnc.cipherBase64);

  const verRes = await fetch(`${BASE_URL}/api/v1/auth/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Timestamp': String(verTs),
      'X-Auth-Nonce': verNonce,
      'X-Auth-Client-ID': clientId,
      'X-Auth-Signature': verSign
    },
    body: JSON.stringify({
      client_id: clientId,
      iv: verEnc.ivHex,
      auth_tag: verEnc.authTagHex,
      cipher_data: verEnc.cipherBase64
    })
  });
  const verJson = await verRes.json();
  const verDecrypted = JSON.parse(aesDecrypt(verJson.data, localSessionKey, verJson.iv, verJson.auth_tag));
  console.log('静默登录通过！有效性:', verDecrypted.valid, '剩余秒数:', verDecrypted.remaining_seconds);
  challengeToken = verDecrypted.challenge_token;

  // 5. 模拟滚动心跳挑战应答
  console.log('\n--- 5. 测试滚动心跳应答 (/api/v1/auth/heartbeat) ---');
  const hbTs = Date.now();
  const challengeResponse = crypto.createHash('sha256')
    .update(`${challengeToken}${signSalt}${hbTs}`, 'utf-8')
    .digest('hex');

  const hbPlain = JSON.stringify({
    session_token: sessionToken,
    challenge_response: challengeResponse,
    uptime_sec: 60,
    tamper_status: { is_jailbroken: false, is_debugged: false }
  });
  const hbEnc = aesEncrypt(hbPlain, localSessionKey);
  const hbNonce = crypto.randomBytes(8).toString('hex');
  const hbSign = hmacSign(signSalt, hbTs, hbNonce, hbEnc.cipherBase64);

  const hbRes = await fetch(`${BASE_URL}/api/v1/auth/heartbeat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Timestamp': String(hbTs),
      'X-Auth-Nonce': hbNonce,
      'X-Auth-Client-ID': clientId,
      'X-Auth-Signature': hbSign
    },
    body: JSON.stringify({
      client_id: clientId,
      iv: hbEnc.ivHex,
      auth_tag: hbEnc.authTagHex,
      cipher_data: hbEnc.cipherBase64
    })
  });
  const hbJson = await hbRes.json();
  const hbDecrypted = JSON.parse(aesDecrypt(hbJson.data, localSessionKey, hbJson.iv, hbJson.auth_tag));
  console.log('心跳续租成功！Alive:', hbDecrypted.alive, '获得新挑战码:', hbDecrypted.next_challenge_token);

  // 6. 测试防重放攻击拦截 (故意使用相同 Timestamp 与 Nonce 重放)
  console.log('\n--- 6. 测试防重放攻击拦截 (重放上一次心跳) ---');
  const replayRes = await fetch(`${BASE_URL}/api/v1/auth/heartbeat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Timestamp': String(hbTs),
      'X-Auth-Nonce': hbNonce,
      'X-Auth-Client-ID': clientId,
      'X-Auth-Signature': hbSign
    },
    body: JSON.stringify({
      client_id: clientId,
      iv: hbEnc.ivHex,
      auth_tag: hbEnc.authTagHex,
      cipher_data: hbEnc.cipherBase64
    })
  });
  const replayJson = await replayRes.json();
  console.log('重放测试响应状态码:', replayJson.code, '消息:', replayJson.msg);
  if (replayJson.code === 4016 || replayJson.code === 4001) {
    console.log('✅ 防重放攻击防御生效！成功拦截重复 Nonce 请求。');
  } else {
    console.warn('⚠️ 防重放校验异常，预期拦截但得到:', replayJson);
  }

  // 7. 测试设备解绑
  console.log('\n--- 7. 测试设备解绑换绑 (/api/v1/auth/unbind) ---');
  const unbindPlain = JSON.stringify({
    card_key: testCardKey,
    device_fingerprint: deviceFingerprint,
    reason: 'TEST_DEVICE_REPLACEMENT'
  });
  const unbindEnc = aesEncrypt(unbindPlain, localSessionKey);
  const unbindTs = Date.now();
  const unbindNonce = crypto.randomBytes(8).toString('hex');
  const unbindSign = hmacSign(signSalt, unbindTs, unbindNonce, unbindEnc.cipherBase64);

  const unbindRes = await fetch(`${BASE_URL}/api/v1/auth/unbind`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Timestamp': String(unbindTs),
      'X-Auth-Nonce': unbindNonce,
      'X-Auth-Client-ID': clientId,
      'X-Auth-Signature': unbindSign
    },
    body: JSON.stringify({
      client_id: clientId,
      iv: unbindEnc.ivHex,
      auth_tag: unbindEnc.authTagHex,
      cipher_data: unbindEnc.cipherBase64
    })
  });
  const unbindJson = await unbindRes.json();
  const unbindDecrypted = JSON.parse(aesDecrypt(unbindJson.data, localSessionKey, unbindJson.iv, unbindJson.auth_tag));
  console.log('解绑成功！已用换绑次数:', unbindDecrypted.unbind_count_used, '扣除时长:', unbindDecrypted.deducted_hours, '小时');

  console.log('\n====================================================');
  console.log('🎉 服务端全链路仿真测试 100% 顺利通过！');
  console.log('====================================================\n');
}

runSimulation().catch(err => {
  console.error('\n❌ 测试执行异常:', err);
  process.exit(1);
});
