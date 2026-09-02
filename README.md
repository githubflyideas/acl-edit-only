# acl-edit-only

H3C 交换机 ACL 审批系统。两进程架构：`aclweb`（Web/DB/审批）永远不持有设备口令；`acl-agent`（telnet/口令）每次执行几秒后退出，不接受网络连接。

---

## 架构概览

```
浏览器 ─→ aclweb (HTTP, SQLite) ─→ sudo acl-agent apply
                                         │
                                    telnet 交换机
```

- `aclweb`：常驻进程，管理用户、审批流、计划文件、日志
- `acl-agent`：短生命周期子进程，唯一持有交换机口令，只接受四条操作：`snapshot / apply / delete / rollback`

---

## 快速部署

### 1. 准备两个 Linux 用户

```bash
useradd -r -s /sbin/nologin aclweb
useradd -r -s /sbin/nologin aclagent
```

### 2. 放置二进制

```bash
cp dist/aclweb-linux-amd64   /usr/local/bin/aclweb
cp dist/aclagent-linux-amd64 /usr/local/bin/aclagent
chown root:root /usr/local/bin/aclweb /usr/local/bin/aclagent
chmod 755 /usr/local/bin/aclweb
chmod 755 /usr/local/bin/aclagent
```

### 3. 准备 acl-agent 的目录和配置

```bash
mkdir -p /etc/aclagent /var/lib/aclagent/plans
chown aclagent:aclagent /etc/aclagent /var/lib/aclagent
chmod 700 /etc/aclagent

# 配置文件
cat > /etc/aclagent/config.json << 'CONF'
{
  "acl":          3977,
  "range_min":    2000,
  "range_max":    4999,
  "alloc_max":    4900,
  "device_addr":  "192.168.1.1:23",
  "credential_file": "/etc/aclagent/credential",
  "plan_dir":     "/var/lib/aclagent/plans",
  "state_file":   "/var/lib/aclagent/state.json",
  "daily_limit":  50,
  "connect_timeout_secs": 10,
  "read_timeout_secs":    15
}
CONF
chown aclagent:aclagent /etc/aclagent/config.json
chmod 400 /etc/aclagent/config.json

# 口令文件：第一行用户名，第二行口令的 base64
printf 'admin\n' > /etc/aclagent/credential
printf 'yourpassword' | base64 >> /etc/aclagent/credential
chown aclagent:aclagent /etc/aclagent/credential
chmod 400 /etc/aclagent/credential
```

### 4. sudo 精确授权（内核强制边界）

```bash
cat > /etc/sudoers.d/aclagent << 'SUDO'
# aclweb 只能以 aclagent 身份运行这一个二进制，不带任何其他命令
aclweb ALL=(aclagent) NOPASSWD: /usr/local/bin/aclagent
SUDO
chmod 440 /etc/sudoers.d/aclagent
visudo -c   # 验证语法
```

### 5. 准备 aclweb 配置

```bash
mkdir -p /etc/aclweb /var/lib/aclweb
chown aclweb:aclweb /etc/aclweb /var/lib/aclweb

cat > /etc/aclweb/config.json << 'CONF'
{
  "listen":   ":8443",
  "tls_cert": "/etc/aclweb/cert.pem",
  "tls_key":  "/etc/aclweb/key.pem",
  "db_path":  "/var/lib/aclweb/aclweb.db",
  "plan_dir": "/var/lib/aclagent/plans",
  "agent_bin": "/usr/local/bin/aclagent",
  "agent_cfg": "/etc/aclagent/config.json",
  "agent_timeout_secs": 60,
  "acl":       3977,
  "range_min": 2000,
  "range_max": 4999,
  "alloc_max": 4900,
  "reconcile_interval_min": 60
}
CONF
chown aclweb:aclweb /etc/aclweb/config.json
chmod 600 /etc/aclweb/config.json
```

TLS 证书自签名示例：

```bash
openssl req -x509 -newkey rsa:4096 -keyout /etc/aclweb/key.pem \
  -out /etc/aclweb/cert.pem -days 365 -nodes \
  -subj "/CN=aclweb"
chown aclweb:aclweb /etc/aclweb/cert.pem /etc/aclweb/key.pem
chmod 600 /etc/aclweb/key.pem
```

### 6. plan_dir 权限

`aclweb` 写计划文件，`aclagent` 读计划文件，两个用户都需要访问：

```bash
chown aclweb:aclagent /var/lib/aclagent/plans
chmod 750 /var/lib/aclagent/plans
```

### 7. 启动（systemd）

`/etc/systemd/system/aclweb.service`：

```ini
[Unit]
Description=H3C ACL Approval Web
After=network.target

[Service]
User=aclweb
ExecStart=/usr/local/bin/aclweb -config /etc/aclweb/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aclweb /var/lib/aclagent/plans

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now aclweb
```

---

## 首次登录

服务启动时如果数据库里没有用户，会自动创建 `admin` 账号并把随机密码打到日志里：

```
INITIAL ADMIN CREATED — username: admin  password: Xk9mP2...
Change this password immediately after first login.
```

```bash
journalctl -u aclweb | grep "INITIAL ADMIN"
```

浏览器访问 `https://<host>:8443`，用上面的密码登录后立即改密。

---

## 用户角色

| 角色 | 提交申请 | 审批/拒绝 | 下发执行 | 用户管理 |
|---|:---:|:---:|:---:|:---:|
| admin | ✓ | ✓ | ✓ | ✓ |
| approver | ✓ | ✓ | — | — |
| operator | ✓ | — | ✓ | — |
| viewer | — | — | — | — |

四眼原则：审批人不能是申请人本人。

---

## 操作流程

```
申请人提交  →  快照设备  →  分配 rule ID  →  生成 diff  →  pending
     ↓
审批人看 diff  →  通过 / 拒绝
     ↓（通过）
操作员下发  →  再次快照（漂移检测）→  调用 acl-agent apply  →  回读验证
     ↓
active（成功）/ dispatch_failed（失败+已回滚）/ inconsistent（需人工介入）
```

---

## acl-agent 直接调用（调试用）

> 正常情况下由 aclweb 通过 sudo 调用，无需手动操作。

```bash
# 抓一份快照
sudo -u aclagent /usr/local/bin/aclagent snapshot \
  --config /etc/aclagent/config.json

# 查看帮助
/usr/local/bin/aclagent --help
```

---

## 安全说明

- 口令是 base64 编码（不是加密）；安全性依赖文件权限 0400 + 属主 `aclagent`
- `acl-agent` 只在 Linux 上运行（依赖 POSIX 权限检查）
- 分页（`---- More ----`）时硬失败，不翻页，防止静默丢行
- `save` 失败不自动回滚，报 `save_failed` 由人决定
- 每条已下发的规则带 `ACLSYS-REQ-<code>-<8hex>` 注释，用于对账

---

## 构建

```bash
git clone https://github.com/githubflyideas/acl-edit-only
cd acl-edit-only

CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/aclagent ./cmd/aclagent/
CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/aclweb   ./cmd/aclweb/
```

Go 1.23+，无 CGo 依赖。
