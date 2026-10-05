# iOS Auth Server (验证管理服务端)

[![Node.js](https://img.shields.io/badge/Node.js-v20%2B-green.svg)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-v4-lightgrey.svg)](https://expressjs.com/)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%7C%20RSA%20%7C%20HMAC-red.svg)]()

本工程为 **iOS 网络验证与 Dylib 注入框架** 的鉴权服务端实现。负责处理客户端握手协商、卡密激活与状态机流转、多因子设备指纹绑定、动态滚动心跳（Challenge-Response）续租、防重放攻击拦截以及管理员卡密生命周期管理。

---

## 1. 核心技术特性

- **纯 JavaScript 零 C++ 原生编译依赖**：采用 Node.js 原生硬件加速 `node:crypto` 实现 2048 位 RSA、AES-256-GCM、HMAC-SHA256、SHA256，跨平台免编译即装即跑。
- **开箱即用密钥对自生**：初次启动自动探测并在 `keys/` 目录生成 2048 位 RSA 公私钥对。
- **原子事务型持久化**：默认提供轻量原子文件存储（`data/auth_store.json`），同时附带标准 MySQL 8 / PostgreSQL 迁移建表脚本（`scripts/schema.sql`）。
- **抗逆向与防伪造协议**：
  - 双向加密信封包装：所有请求与响应业务内容均经 AES-256-GCM 加密，外部只能看到 `iv`, `auth_tag`, `cipher_data`。
  - 防重放：$\le 30$ 秒时钟偏差窗口 + 内存/Redis 原子 Nonce 60 秒一次一密拦截。
  - 心跳挑战应答：客户端与服务端共享滚动随机种子，阻断本地伪造或 Hook 静态返回。

---

## 2. 目录结构

```
server/
├── data/                       # 数据持久化目录 (自动生成 auth_store.json)
├── keys/                       # 服务端 RSA 公私钥 (首次启动自动生成)
├── scripts/
│   └── schema.sql              # MySQL/PostgreSQL 生产建表脚本
├── src/
│   ├── config/index.js         # 全局配置
│   ├── crypto/                 # 密码学核心 (AES-256-GCM, RSA, HMAC, KeyManager)
│   ├── storage/                # 存储引擎与数据仓储层 (Card, Binding, Session, Nonce)
│   ├── middleware/             # 安全中间件 (防重放、签名校验、信封解密、统一响应)
│   ├── services/               # 业务逻辑 (握手、激活、验证、心跳、解绑、卡密生成)
│   ├── controllers/            # 路由控制器
│   ├── routes/                 # 鉴权与管理路由注册
│   └── app.js                  # Express 实例配置
├── tests/
│   └── simulate_client.js      # 全链路协议仿真联调测试脚本
├── index.js                    # 服务启动入口
└── package.json
```

---

## 3. 快速启动与调试

### 3.1 安装依赖
在 `server` 目录下执行：
```bash
npm install
```

### 3.2 启动服务
```bash
npm start
```
服务默认监听在 `http://0.0.0.0:8080`。

### 3.3 运行全链路仿真客户端测试
确保服务启动后，在另一个终端执行：
```bash
npm run test:client
```
测试脚本将完整覆盖：
1. 握手与 RSA 协商临时会话密钥
2. 管理端生成测试卡密
3. 客户端采集设备指纹并加密激活
4. 冷启动静默快速验证
5. 动态心跳 Challenge-Response 计算与续租
6. 重放攻击测试（主动复用 Nonce 验证 4001 拦截）
7. 设备解绑申请

---

## 4. 生产环境部署建议

- **生产环境变量**：
  ```bash
  PORT=8080
  NODE_ENV=production
  ADMIN_API_KEY=your_high_strength_admin_secret
  DEFAULT_SIGN_SALT=your_custom_salt_value
  ```
- **反向代理**：建议在公网通过 Nginx / Caddy 开启 HTTPS 并配置 SSL 证书。
- **数据库迁移**：当卡密规模超过 5 万条或有多节点横向扩展需求时，可导入 `scripts/schema.sql` 并将 `src/storage/repository.js` 适配至 MySQL 或 PostgreSQL 连接池。
