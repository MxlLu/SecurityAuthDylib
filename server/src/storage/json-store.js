import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config/index.js';

let storeCache = null;

const defaultData = {
  cards: [],
  bindings: [],
  audit_logs: []
};

/**
 * 初始化存储
 */
export function initStore() {
  if (!fs.existsSync(config.paths.dataDir)) {
    fs.mkdirSync(config.paths.dataDir, { recursive: true });
  }

  if (fs.existsSync(config.paths.storageFilePath)) {
    try {
      const raw = fs.readFileSync(config.paths.storageFilePath, 'utf-8');
      storeCache = JSON.parse(raw);
    } catch (err) {
      console.error('[JsonStore] 解析持久化存储文件失败，重置为默认数据:', err.message);
      storeCache = JSON.parse(JSON.stringify(defaultData));
      persist();
    }
  } else {
    storeCache = JSON.parse(JSON.stringify(defaultData));
    persist();
  }

  return storeCache;
}

export function getStore() {
  if (!storeCache) {
    initStore();
  }
  return storeCache;
}

/**
 * 原子性写盘持久化
 */
export function persist() {
  if (!storeCache) return;
  const tmpPath = `${config.paths.storageFilePath}.tmp`;
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(storeCache, null, 2), 'utf-8');
    fs.renameSync(tmpPath, config.paths.storageFilePath);
  } catch (err) {
    console.error('[JsonStore] 写入数据文件失败:', err);
  }
}
