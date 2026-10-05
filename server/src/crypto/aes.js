import crypto from 'node:crypto';

/**
 * 使用 AES-256-GCM 加密明文字符串或 Buffer
 * @param {string|Buffer} plaintext 明文数据
 * @param {Buffer} key 32 字节密钥
 * @returns {{ cipherBase64: string, ivHex: string, authTagHex: string }}
 */
export function encryptAesGcm(plaintext, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error('AES-256-GCM 密钥必须为 32 字节 Buffer');
  }

  // 生成 12 字节随机 IV
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const plainBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    cipherBase64: encrypted.toString('base64'),
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex')
  };
}

/**
 * 使用 AES-256-GCM 解密密文
 * @param {string} cipherBase64 Base64 编码的密文
 * @param {Buffer} key 32 字节密钥
 * @param {string} ivHex 24 字符十六进制 IV (12 字节)
 * @param {string} authTagHex 32 字符十六进制 AuthTag (16 字节)
 * @returns {string} 解密后的明文字符串
 */
export function decryptAesGcm(cipherBase64, key, ivHex, authTagHex) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error('AES-256-GCM 密钥必须为 32 字节 Buffer');
  }

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const cipherBuffer = Buffer.from(cipherBase64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(cipherBuffer), decipher.final()]);
  return decrypted.toString('utf-8');
}
