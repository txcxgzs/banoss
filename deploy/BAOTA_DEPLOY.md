# 宝塔面板 + 域名 + Cloudflare 部署指南

严格遵循宝塔面板标准目录与反向代理规范，推荐部署路径为 `/www/wwwroot/oss.你的域名`（下文以 `/www/wwwroot/banoss` 为例）。

---

## 第一步：上传代码并配置环境变量

将项目文件上传到服务器 `/www/wwwroot/banoss` 后，准备 `.env`：

```bash
cd /www/wwwroot/banoss
cp .env.example .env
```

编辑 `.env`（**务必修改为强 Token 与你的真实域名**）：

```ini
BANOSS_HOST=127.0.0.1
BANOSS_PORT=9000
BANOSS_DATA_DIR=/www/wwwroot/banoss/data
BANOSS_ADMIN_TOKEN=换成你自己生成的32位以上随机管理员Token
BANOSS_BASE_DOMAINS=["oss.你的域名.com","127.0.0.1"]
BANOSS_CHUNK_SIZE=1048576
BANOSS_SFTP_IDLE_TIMEOUT=60
```

> 安全提醒：`BANOSS_HOST=127.0.0.1` 表示只监听本机回环，外部全部由宝塔 Nginx 走 HTTPS 反代进来；**不要在宝塔安全组对外放行 `9000` 端口**。

---

## 第二步：在宝塔启动 BanOSS 进程（二选一）

### 方式 A：宝塔「Python 项目管理器」（推荐，轻量直接）
1. 在宝塔面板 **软件商店** 安装 **Python 项目管理器**（或直接用宝塔内置网站 -> Python 项目），添加 Python `3.12`。
2. **网站 → Python 项目 → 添加 Python 项目**：
   * **项目路径**：`/www/wwwroot/banoss`
   * **Python 版本**：`3.12`
   * **启动方式**：选 `自定义` / `Uvicorn`，启动命令填：
     ```bash
     uvicorn main:app --host 127.0.0.1 --port 9000 --workers 1
     ```
     *(注：因内置 SQLite 与 SFTP 内存连接池，`--workers` 保持 `1`，单进程异步可轻松支撑高并发流式转发。)*
   * **端口**：`9000`
   * **包管理**：勾选安装 `requirements.txt`（已包含全部依赖）。
3. 建议在宝塔确认 **开机自启** 已打开。

### 方式 B：宝塔「Docker 管理器」
直接进入 `/www/wwwroot/banoss` 执行：
```bash
docker compose up -d --build
```
*(若用 Docker，`.env` 中 `BANOSS_HOST` 保持 `0.0.0.0`，但 `docker-compose.yml` 端口映射可改为 `127.0.0.1:9000:9000`。)*

---

## 第三步：在宝塔配置网站与 Nginx 反向代理（避坑关键）

1. 在宝塔 **网站 → PHP项目（或纯静态）→ 添加站点**：
   * 域名填：`oss.你的域名.com`
   * PHP 版本选：**纯静态**
2. **申请 SSL 证书**：
   * 若域名先不走 CF 或验证放行：在站点 **SSL → Let's Encrypt** 直接申请并开启「强制 HTTPS」；
   * 若已全程走 Cloudflare 小黄云（Proxied）：也可在 Cloudflare 控制台 **SSL/TLS → 源服务器** 生成 15 年有效期 Origin Certificate，贴入宝塔站点 **SSL → 其他证书**。
3. **修改站点配置文件（最关键！）**：
   * 打开站点 **设置 → 配置文件**，参考 [baota-nginx.conf](baota-nginx.conf)：
   * **必须删除宝塔默认自带的以下两段正则规则**，否则 S3 里的图片/JS/CSS 文件会全部被拦截成 404：
     ```nginx
     location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$ { ... }
     location ~ .*\.(js|css)?$ { ... }
     ```
   * 确保 `location /` 内包含：
     * `proxy_pass http://127.0.0.1:9000;`
     * `proxy_set_header Host $http_host;`（**必须保留 `$http_host` 才能过 SigV4 验签**）
     * `client_max_body_size 0;`
     * `proxy_request_buffering off;`
     * `proxy_buffering off;`

---

## 第四步：Cloudflare (CF) 必调项（避坑！）

1. **SSL/TLS 加密模式**：
   在 CF 后台 **SSL/TLS → 概述** 设为 **完全（严格）/ Full (strict)**，避免“重定向次数过多”。
2. **单次上传 100 MB 限制与大文件对策**：
   * Cloudflare 免费版开启小黄云（Proxied）时，**单次 HTTP 请求 Body 上限为 100 MB**（超出会返回 `413`）。
   * **大文件接入做法**：使用 `rclone` / `boto3` 上传大文件时，将分片大小设为 **16 MB ~ 50 MB**（远小于 100 MB）：
     * `rclone` 配置增加：`chunk_size = 32M`（或命令行 `--s3-chunk-size 32M`），几十 GB 文件照样穿过 CF 小黄云！
     * `boto3` 配置：`TransferConfig(multipart_chunksize=32 * 1024 * 1024)`。
   * 如果网页端 `/console` 也需要频繁直接拖拽上传单文件超过 100 MB，可以额外在 CF 加一条 **仅 DNS（灰云）** 子域名（例如 `direct-oss.你的域名.com`），只用于内网/直连上传。
3. **S3 地址风格**：
   CF 免费通用证书只覆盖一级通配符（`*.你的域名.com`），不覆盖 `*.oss.你的域名.com`。因此所有 S3 客户端均建议使用 **Path-Style（路径风格，例如 `https://oss.你的域名.com/bucket/key`）**。

---

## 第五步：日常灾备与恢复

1. 在管理台 `https://oss.你的域名.com/admin` 的 **概览与接入** 页面，输入 8 位以上强口令，点击 **「下载加密灾备包 (.vault)」** 或 **「一键加密推送到选定节点」**。
2. 如需在新服务器恢复整个网关：
   ```bash
   banoss restore --vault banoss-vault-xxxx.vault --data-dir /www/wwwroot/banoss/data
   ```
   恢复后重启 BanOSS 进程即可立即接管所有超算密文数据。
