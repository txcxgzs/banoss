# BanOSS

面向多用户与多 SFTP 存储后端的轻量 S3 兼容对象存储网关（Python 3.12 + FastAPI + SQLite + asyncssh）。

## 核心特性

* **远端零常驻**：只通过标准 SSH/SFTP 按需读写，网关侧内置每节点并发信号量控制与空闲超时自动断连池（`idle_timeout_sec`）。
* **SQLite 元数据索引**：`ListObjectsV2` / `HeadObject` / `ListBuckets` 直接走本地 SQLite WAL，查询零 SFTP 连接开销。
* **多用户与绑定路由**：
  * 每个 S3 用户拥有独立 `Access Key` / `Secret Key`（支持 AWS SigV4 请求头鉴权、SigV4/SigV2 预签名 URL）。
  * 用户显式绑定一个或多个 SFTP / Local 存储节点，按优先级与剩余配额自动写入路由、按索引精确回源读取。
* **Bucket 权限与 CORS 跨域**：支持 `private`（私有）与 `public-read`（公共读免签直链下载），支持 `OPTIONS` 预检与自定义 CORS 规则。
* **分块透明加密（AES-256-GCM）**：
  * 服务端自动为每段数据生成独立 DEK 并用主密钥（KEK）包封保存；
  * 默认按 `1 MiB` 分块加密，支持 **O(1) 随机偏移 `Range` 断点续传**与流式解密。
* **分片上传（Multipart Upload）**：支持完整 S3 分片接口，合并时基于 SQLite 段清单瞬时提交，无需二次拉取重组。
* **双入口 Web 控制台**：
  * **用户自助台 (`/console`)**：普通用户用自己的 `AK/SK` 登录，管理个人 Bucket、文件夹面包屑、拖拽上传（带进度条）、外链分享、在线预览（图片/文本/PDF/音视频）、批量删除、ACL 与 CORS。
  * **超级管理员台 (`/admin`)**：用 `Admin Token` 登录，管理 SFTP 节点探活、多用户 AK/SK、节点绑定与全局数据。

## 服务器部署方式

### 方式 1：Docker Compose 一键部署（推荐）

```bash
cp .env.example .env
# 按需修改 .env 中的 BANOSS_ADMIN_TOKEN 与 BANOSS_BASE_DOMAINS
docker compose up -d --build
```

数据会持久化在宿主机 `./data`（包含 `banoss.db`、`.master.key`、`.admin.token`），**务必定期备份 `.master.key` 与 `banoss.db`**。

### 方式 2：直接用 `uv` 启动 / `systemd` 托管

```bash
uv sync --extra dev
uv run banoss --host 127.0.0.1 --port 9000
```

如需生产环境用 Nginx 反代并开启 HTTPS，可参考 [nginx.conf](deploy/nginx.conf)（已关闭请求/响应缓冲以支持大文件流式传输）和 [banoss.service](deploy/banoss.service)。

## 运行测试

```bash
uv run pytest -v
```

## 客户端接入示例

### Python (`boto3`)

```python
import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:9000",
    aws_access_key_id="你的_AK",
    aws_secret_access_key="你的_SK",
    region_name="us-east-1",
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)

s3.create_bucket(Bucket="my-bucket")
s3.upload_file("local.tar.gz", "my-bucket", "backups/local.tar.gz")
```

### `rclone`

```ini
[banoss]
type = s3
provider = Other
access_key_id = 你的_AK
secret_access_key = 你的_SK
endpoint = http://127.0.0.1:9000
force_path_style = true
```
