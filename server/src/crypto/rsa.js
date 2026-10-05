import crypto from 'node:crypto';
import { getPrivateKey, getPublicKey } from './key-manager.js';

/**
 * 使用服务端 RSA 私钥解密客户端上送的密文（如会话密钥）
 * @param {string} encryptedBase64 Base64 编码的密文
 * @returns {Buffer} 解密后的明文 Buffer
 */
export function decryptWithServerPrivateKey(encryptedBase64) {
  const privateKey = getPrivateKey();
  const buffer = Buffer.from(encryptedBase64, 'base64');
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    buffer
  );
}

/**
 * 使用服务端公钥加密数据（主要用于客户端测试模拟器）
 * @param {Buffer|string} data 
 * @returns {string} Base64 编码的密文
 */
export function encryptWithServerPublicKey(data) {
  const publicKey = getPublicKey();
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf-8');
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    buffer
  );
  return encrypted.toString('base64');
}
