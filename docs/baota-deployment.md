# 宝塔面板 (aaPanel) 部署与上线完整指南

本服务端采用 **纯 JavaScript + Node.js 原生硬件加速加密体系**，无任何本地 C++ 编译依赖，在宝塔面板（CentOS / Ubuntu / Debian）上具有极高的兼容性，安装与运行非常顺畅。

---

## 1. 为什么推荐部署在宝塔？

1. **iOS 强制 HTTPS (ATS 要求)**：iOS 客户端禁止普通明文 HTTP 请求，宝塔面板支持**一键申请与自动续期免费 SSL 证书**。
2. **PM2 进程守护**：宝塔 Node 项目自带 PM2 进程保活，开机自启、崩溃自动恢复。
3. **极速零报错依赖安装**：纯 JS 架构，在 Linux 服务器执行 `npm install` 仅需 2~3 秒，不会遇到 `node-gyp` 或 GCC 编译报错。

---

## 2. 宝塔面板部署实操步骤

### 第一步：安装 Node.js 环境
1. 登录宝塔面板后台 $\to$ 点击左侧【软件商店】；
2. 搜索并安装 **Node.js版本管理器**（或直接在【网站】$\to$【Node项目】中添加）；
3. 打开 Node.js 版本管理器，安装 **`v20.x` LTS**（推荐 v20.18 或以上）并设置为命令行默认版本。

---

### 第二步：上传服务端代码
1. 在宝塔面板左侧点击【文件】；
2. 进入目录 `/www/wwwroot/`，新建目录（如 `ios-auth-server`）；
3. 将本项目下的 `server/` 目录内容打包压缩并上传至该目录解压：
   ```
   /www/wwwroot/ios-auth-server/
   ├── data/
   ├── keys/
   ├── scripts/
   ├── src/
   ├── tests/
   ├── config.json
   ├── index.js
   ├── package.json
   └── README.md
   ```

---

### 第三步：依赖说明与添加 Node 项目
1. **依赖说明 (开箱即用)**：
   - 最新的部署包 `ios-auth-server-baota-4090.zip` 已**全内置完整依赖**（仅 898KB，纯 JS 跨平台通用），**解压后可直接运行，无需再执行 npm install**。
   - 若您希望在服务器上全新重装依赖，建议使用国内高速镜像源（避免官方源超时导致依赖文件下载不全）：
     ```bash
     cd /www/wwwroot/ios-auth-server
     npm install --registry=https://registry.npmmirror.com --production
     ```
2. **添加 Node 项目**：
   - 宝塔面板点击左侧【网站】 $\to$ 【Node项目】 $\to$ 【添加Node项目】；
   - **项目名称**：`ios-auth-server`
   - **项目目录**：`/www/wwwroot/ios-auth-server`
   - **启动选项**：`index.js`
   - **项目端口**：`4090`
   - **运行用户**：`www`
   - **Node版本**：选择刚才安装的 `v20.x`
   - 点击【提交】，宝塔将通过 PM2 自动启动服务。
   - 首次启动时，程序会自动在 `keys/` 目录下生成服务端 RSA 密钥对，在 `data/` 目录下生成数据持久化文件。

---

### 第四步：绑定域名与配置 SSL 证书 (核心)

由于 iOS 必须通过安全的 HTTPS 协议通信：
1. **添加域名**：
   - 在刚才创建的 Node 项目设置中，绑定您的解析域名（例如 `auth.yourdomain.com`）。
2. **申请与配置 SSL 证书**：
   - 点击该项目设置中的【SSL】标签页；
   - 选择【Let's Encrypt】或上传已有商业证书，勾选域名点击【申请】；
   - 申请成功后勾选【强制 HTTPS】。
3. **验证反向代理**：
   - 宝塔会自动将外网 443 端口的请求通过 Nginx 代理至内部 `127.0.0.1:4090`。

---

### 第五步：防火墙与连通性验证

1. **防火墙放行**：
   - 宝塔【安全】页面与云厂商安全组（阿里云/腾讯云等）确保放行 **80** 与 **443** 端口。
2. **访问健康检查端点**：
   - 浏览器或终端请求：
     ```bash
     curl https://auth.yourdomain.com/health
     ```
   - 返回 `{"status":"UP","service":"iOS Network License Server"}` 即代表公网部署成功！

---

## 3. 日常卡密运维与管理

在服务器终端进入项目目录，即可直接使用内置的 CLI 工具进行卡密操作：

```bash
cd /www/wwwroot/ios-auth-server

# 1. 创建一张自定义卡密 (例如月卡，绑定2台设备)
node scripts/manage_cards.js create --key "VIP-ONLINE-8888" --type MONTHLY --devices 2 --note "线上第一批用户"

# 2. 批量生成10张天卡
node scripts/manage_cards.js batch --count 10 --type DAILY --prefix PRO

# 3. 查看当前卡密激活与设备绑定情况
node scripts/manage_cards.js list

# 4. 强制解绑/重置某张卡密
node scripts/manage_cards.js reset --key "VIP-ONLINE-8888"

# 5. 修改业务参数 (例如修改心跳为30秒，发布系统公告)
node scripts/manage_cards.js set-config --heartbeat 30 --announcement "欢迎使用最新授权服务"
```

---

## 4. 客户端 Dylib 对接配合

服务端在宝塔上线并配置好域名证书后，只需在客户端 [client/SecurityAuthDylib/src/Entry.m](file:///d:/iosss/client/SecurityAuthDylib/src/Entry.m) 中同步修改两处：

1. **通信地址**：
   ```objc
   [AuthConfig sharedInstance].serverURL = @"https://auth.yourdomain.com";
   ```
2. **服务端 RSA 公钥**：
   将宝塔服务器上 `/www/wwwroot/ios-auth-server/keys/server_public.pem` 的公钥内容复制到客户端 `Entry.m` 的 `embeddedServerPubKey` 即可！
