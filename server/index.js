import { config } from './src/config/index.js';
import { initKeys } from './src/crypto/key-manager.js';
import { initStore } from './src/storage/json-store.js';
import { createApp } from './src/app.js';

async function bootstrap() {
  console.log('====================================================');
  console.log('   iOS Network License & Dylib Auth Server');
  console.log('====================================================');

  // 1. 初始化密码学密钥
  initKeys();

  // 2. 初始化持久化存储
  initStore();

  // 3. 构建与启动 Express 服务
  const app = createApp();

  const server = app.listen(config.port, config.host, () => {
    console.log(`[Server] 服务已启动: http://${config.host}:${config.port}`);
    console.log(`[Server] 健康检查:   http://${config.host}:${config.port}/health`);
    console.log(`[Server] 鉴权端点:   http://${config.host}:${config.port}/api/v1/auth/*`);
    console.log(`[Server] 管理端点:   http://${config.host}:${config.port}/api/v1/admin/*`);
    console.log(`[Server] 数据文件:   ${config.paths.storageFilePath}`);
    console.log(`[Server] RSA 公钥:   ${config.paths.publicKeyPath}`);
    console.log('====================================================');
  });

  // 优雅停机
  const handleShutdown = (signal) => {
    console.log(`\n[Server] 收到信号 ${signal}，正在关闭服务器...`);
    server.close(() => {
      console.log('[Server] 服务已安全关闭。');
      process.exit(0);
    });
  };

  process.on('SIGINT', () => handleShutdown('SIGINT'));
  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
}

bootstrap().catch(err => {
  console.error('[Bootstrap] 启动失败:', err);
  process.exit(1);
});
