import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from '../config/index.js';

let privateKey = null;
let publicKey = null;

/**
 * 初始化或加载服务端 RSA 密钥对
 */
export function initKeys() {
  if (!fs.existsSync(config.paths.keysDir)) {
    fs.mkdirSync(config.paths.keysDir, { recursive: true });
  }

  const pubExists = fs.existsSync(config.paths.publicKeyPath);
  const privExists = fs.existsSync(config.paths.privateKeyPath);

  if (!pubExists || !privExists) {
    console.log('[KeyManager] 未检测到 RSA 密钥对，正在自动生成 2048 位服务端密钥对...');
    const { publicKey: generatedPub, privateKey: generatedPriv } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    fs.writeFileSync(config.paths.publicKeyPath, generatedPub, 'utf-8');
    fs.writeFileSync(config.paths.privateKeyPath, generatedPriv, 'utf-8');
    publicKey = generatedPub;
    privateKey = generatedPriv;
    console.log('[KeyManager] RSA 密钥对已生成并保存至 keys/ 目录。');
  } else {
    publicKey = fs.readFileSync(config.paths.publicKeyPath, 'utf-8');
    privateKey = fs.readFileSync(config.paths.privateKeyPath, 'utf-8');
    console.log('[KeyManager] 已成功加载现有 RSA 服务端公私钥。');
  }

  return { publicKey, privateKey };
}

export function getPublicKey() {
  if (!publicKey) initKeys();
  return publicKey;
}

export function getPrivateKey() {
  if (!privateKey) initKeys();
  return privateKey;
}
