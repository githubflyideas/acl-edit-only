# acl-edit-only

H3C 交换机 ACL 审批系统。两进程架构：`aclweb`（Web/DB）永远不持有设备口令；`acl-agent`（telnet/口令）每次执行几秒后退出。

操作流程：提交申请 → 看 diff → 确认执行 → 实时看终端输出。

---

## 部署

### 1. 放置二进制

```bash
cp dist/aclweb-linux-amd64   /usr/local/bin/aclweb
cp dist/aclagent-linux-amd64 /usr/local/bin/aclagent
chmod 755 /usr/local/bin/aclweb /usr/local/bin/aclagent
```

### 2. acl-agent 配置

```bash
mkdir -p /etc/aclagent /var/lib/aclagent/plans
chmod 700 /etc/aclagent

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
chmod 400 /etc/aclagent/config.json

# 口令文件：第一行用户名，第二行口令的 base64
printf 'admin\n' > /etc/aclagent/credential
printf 'yourpassword' | base64 >> /etc/aclagent/credential
chmod 400 /etc/aclagent/credential
```

| 字段 | 说明 |
|---|---|
| `acl` | 目标 ACL 编号 |
| `range_min` / `range_max` | rule ID 合法范围 |
| `alloc_max` | 自动分配上限（≤ range_max，可留出保留区） |
| `daily_limit` | 每日 apply 次数上限 |
| `device_addr` | 交换机 IP:端口（telnet，通常 23） |

### 3. aclweb 配置

```bash
mkdir -p /etc/aclweb /var/lib/aclweb

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
```

`acl` / `range_min` / `range_max` / `alloc_max` 必须与 acl-agent 配置一致。

不需要 TLS（内网）：去掉 `tls_cert` 和 `tls_key`，改用明文 HTTP。

自签名证书：

```bash
openssl req -x509 -newkey rsa:4096 -keyout /etc/aclweb/key.pem \
  -out /etc/aclweb/cert.pem -days 365 -nodes -subj "/CN=aclweb"
chmod 600 /etc/aclweb/key.pem
```

### 4. 启动

```bash
/usr/local/bin/aclweb -config /etc/aclweb/config.json
```

systemd：

```ini
[Unit]
Description=H3C ACL Approval Web
After=network.target

[Service]
ExecStart=/usr/local/bin/aclweb -config /etc/aclweb/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## 首次登录

启动时若数据库没有用户，自动创建 `admin` 并把随机密码打到日志：

```
INITIAL ADMIN CREATED — username: admin  password: Xk9mP2...
```

```bash
journalctl -u aclweb | grep "INITIAL ADMIN"
```

访问 `https://<host>:8443`，登录后立即改密。

---

## 操作流程

1. **提交申请** — 填写目的 IP、端口、协议、原因
2. **看 diff** — 系统从设备抓快照，生成预期变更的 unified diff
3. **确认执行** — 核对无误后点击，页面展开终端窗口，实时显示 telnet 连接和命令执行过程
4. **自动验证** — 回读设备，断言规则条数 +1、新规则存在、其余规则未变
5. 成功 → `active`；失败自动回滚 → `dispatch_failed`；回滚也失败 → `inconsistent`（需人工介入）

删除规则走同样的流程（在 active 规则详情页申请删除）。

---

## 安全说明

- 口令是 base64 编码，安全性依赖文件权限 `0400`
- `acl-agent` 只在 Linux 上启动
- 遇到分页（`---- More ----`）硬失败，不翻页
- `save` 失败不自动回滚，报 `save_failed` 由人决定
- 每条规则带 `ACLSYS-REQ-<code>-<8hex>` 注释，用于对账

---

## 从源码构建

```bash
git clone https://github.com/githubflyideas/acl-edit-only
cd acl-edit-only

CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/aclagent ./cmd/aclagent/
CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/aclweb   ./cmd/aclweb/
```

Go 1.23+，无 CGo 依赖。
