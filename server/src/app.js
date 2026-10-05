import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { responseHelper } from './middleware/security.js';
import authRoutes from './routes/auth-routes.js';
import adminRoutes from './routes/admin-routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicAdminDir = path.resolve(__dirname, '../public/admin');

export function createApp() {
  const app = express();

  // 基础中间件
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true }));

  // 统一响应封装助手
  app.use(responseHelper);

  // 静态 Web 控制台托管
  app.use('/admin', express.static(publicAdminDir));
  app.get('/', (req, res) => res.redirect('/admin'));

  // 健康检查
  app.get('/health', (req, res) => {
    res.json({
      status: 'UP',
      time: new Date().toISOString(),
      service: 'iOS Network License Server'
    });
  });

  // 业务路由注册
  app.use('/api/v1/auth', authRoutes);
  app.use('/api/v1/admin', adminRoutes);

  // 404 处理
  app.use((req, res) => {
    res.status(404).json({ code: 404, msg: `路由未找到: ${req.method} ${req.url}` });
  });

  // 全局错误捕获
  app.use((err, req, res, next) => {
    console.error('[App] 未捕获异常:', err);
    res.status(500).json({ code: 5000, msg: '服务端内部异常' });
  });

  return app;
}
