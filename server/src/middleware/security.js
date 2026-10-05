import crypto from 'node:crypto';
import { config } from '../config/index.js';
import { nonceRepo, sessionRepo } from '../storage/repository.js';
import { decryptWithServerPrivateKey } from '../crypto/rsa.js';
import { decryptAesGcm, encryptAesGcm } from '../crypto/aes.js';
import { calculateSignature, verifySignature } from '../crypto/signature.js';

/**
 * 响应体封装与加解密中间件
 */
export function responseHelper(req, res, next) {
  // 发送错误响应
  res.sendError = (code, msg, httpStatus = 200) => {
    return res.status(httpStatus).json({
      code,
      msg,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
      iv: '',
      auth_tag: '',
      data: ''
    });
  };

  // 发送加密业务响应
  res.sendEncrypted = (dataObj, sessionKeyBuffer) => {
    try {
      const plainStr = JSON.stringify(dataObj);
      const { cipherBase64, ivHex, authTagHex } = encryptAesGcm(plainStr, sessionKeyBuffer);
      return res.status(200).json({
        code: 0,
        msg: 'success',
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        iv: ivHex,
        auth_tag: authTagHex,
        data: cipherBase64
      });
    } catch (err) {
      console.error('[ResponseHelper] 加密响应失败:', err);
      return res.sendError(5000, '响应加密异常');
    }
  };

  next();
}

/**
 * 防重放攻击校验中间件
 */
export function replayDefense(req, res, next) {
  const timestampStr = req.headers['x-auth-timestamp'];
  const nonce = req.headers['x-auth-nonce'];

  if (!timestampStr || !nonce) {
    return res.sendError(4000, '缺少防重放请求头 (X-Auth-Timestamp / X-Auth-Nonce)');
  }

  const clientTs = parseInt(timestampStr, 10);
  if (isNaN(clientTs)) {
    return res.sendError(4000, '非法时间戳格式');
  }

  // 1. 时钟偏差校验
  const now = Date.now();
  if (Math.abs(now - clientTs) > config.security.allowedClockSkewMs) {
    return res.sendError(4001, `时钟偏差过大 (差值: ${Math.abs(now - clientTs)}ms，允许: ${config.security.allowedClockSkewMs}ms)`);
  }

  // 2. Nonce 一次一密校验
  const isFresh = nonceRepo.checkAndStore(nonce, config.security.nonceTtlSec);
  if (!isFresh) {
    return res.sendError(4001, '检测到重放攻击 (Nonce 已被使用)');
  }

  req.authContext = {
    clientTimestamp: clientTs,
    nonce,
    clientId: req.headers['x-auth-client-id'] || null,
    signature: req.headers['x-auth-signature'] || null
  };

  next();
}

/**
 * 握手专用解密与签名校验中间件
 */
export function handshakeSecurity(req, res, next) {
  const { encrypted_session_key } = req.body;
  if (!encrypted_session_key) {
    return res.sendError(4000, '缺少加密会话密钥 (encrypted_session_key)');
  }

  try {
    // 1. 服务端 RSA 私钥解密获取客户端 SessionKey (32字节)
    const sessionKeyBuffer = decryptWithServerPrivateKey(encrypted_session_key);
    if (sessionKeyBuffer.length !== 32) {
      return res.sendError(4003, '协商会话密钥长度非法 (必须为 32 字节)');
    }

    // 2. 校验签名 (使用默认签名盐或会话密钥)
    const signature = req.authContext.signature;
    if (signature) {
      const expected = calculateSignature(
        config.security.defaultSignSalt,
        req.authContext.clientTimestamp,
        req.authContext.nonce,
        req.body.cipher_data || encrypted_session_key
      );
      if (!verifySignature(expected, signature)) {
        return res.sendError(4002, '握手请求签名校验失败');
      }
    }

    req.sessionKeyBuffer = sessionKeyBuffer;
    next();
  } catch (err) {
    console.error('[HandshakeSecurity] RSA 解密失败:', err.message);
    return res.sendError(4003, 'RSA 会话密钥解密失败');
  }
}

/**
 * 常规业务接口解密与签名校验中间件
 */
export function businessSecurity(req, res, next) {
  const { client_id, iv, auth_tag, cipher_data } = req.body;
  const headerClientId = req.authContext.clientId || client_id;

  if (!headerClientId) {
    return res.sendError(4000, '缺少客户端会话标识 (X-Auth-Client-ID)');
  }

  const session = sessionRepo.getSessionByClientId(headerClientId);
  if (!session) {
    return res.sendError(4004, '会话已失效或未建立握手，请重新握手');
  }

  // 1. 签名校验
  const signature = req.authContext.signature;
  if (!signature) {
    return res.sendError(4002, '缺少请求签名 (X-Auth-Signature)');
  }

  const expectedSig = calculateSignature(
    session.signSalt,
    req.authContext.clientTimestamp,
    req.authContext.nonce,
    cipher_data
  );

  if (!verifySignature(expectedSig, signature)) {
    return res.sendError(4002, '请求签名校验不合法');
  }

  // 2. AES-256-GCM 解密
  if (!iv || !auth_tag || !cipher_data) {
    return res.sendError(4000, '密文外壳参数缺失 (iv / auth_tag / cipher_data)');
  }

  try {
    const plainText = decryptAesGcm(cipher_data, session.sessionKey, iv, auth_tag);
    req.decryptedBody = JSON.parse(plainText);
    req.session = session;
    next();
  } catch (err) {
    console.error('[BusinessSecurity] AES 解密失败:', err.message);
    return res.sendError(4003, '密文载荷解密失败 (AuthTag 校验失败)');
  }
}
