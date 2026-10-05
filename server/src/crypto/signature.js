import crypto from 'node:crypto';

/**
 * 计算 HMAC-SHA256 签名
 * 签名规则: HMAC-SHA256(SignKey, Timestamp + "&" + Nonce + "&" + CipherPayload)
 * @param {string} signKey 签名盐值 / 密钥
 * @param {number|string} timestamp 客户端毫秒时间戳
 * @param {string} nonce 随机数
 * @param {string} payloadBody 密文字符串 (cipher_data 或原始请求体)
 * @returns {string} 64 位十六进制签名小写字符串
 */
export function calculateSignature(signKey, timestamp, nonce, payloadBody) {
  const content = `${timestamp}&${nonce}&${payloadBody || ''}`;
  return crypto.createHmac('sha256', signKey).update(content, 'utf-8').digest('hex');
}

/**
 * 安全校验签名（时间常数抗侧信道攻击比对）
 * @param {string} expectedSig 预期的合法签名
 * @param {string} incomingSig 传入的签名
 * @returns {boolean}
 */
export function verifySignature(expectedSig, incomingSig) {
  if (!expectedSig || !incomingSig) return false;
  const expBuf = Buffer.from(expectedSig.toLowerCase(), 'utf-8');
  const incBuf = Buffer.from(incomingSig.toLowerCase(), 'utf-8');
  if (expBuf.length !== incBuf.length) return false;
  return crypto.timingSafeEqual(expBuf, incBuf);
}

/**
 * 校验心跳滚动挑战码应答
 * 应答规则: SHA256(challenge_token + sign_salt + timestamp)
 */
export function verifyChallengeResponse(challengeToken, signSalt, timestamp, responseHash) {
  const expected = crypto.createHash('sha256')
    .update(`${challengeToken}${signSalt}${timestamp}`, 'utf-8')
    .digest('hex');
  return verifySignature(expected, responseHash);
}
