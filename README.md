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
  "connect_timeout_s": 10,
  "read_timeout_s":    15
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
  "rule_comment": false,
  "reconcile_interval_min": 60
}
CONF
```

`acl` / `range_min` / `range_max` / `alloc_max` 必须与 acl-agent 配置一致。

`rule_comment` 决定要不要在每条规则下面再写一行 `rule <N> comment ACLSYS-REQ-<code>-<8hex>`。默认 `false`，一次审批只往交换机上加一行。改成 `true` 的唯一好处是有人直接看 `display acl` 时能分辨哪些规则是本工具建的；对账不依赖它，对账是拿数据库里记录的 rule ID 去快照里查。

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

## 对真机做只读验证

在把 Web 端接到生产交换机之前，先用 agent 的 `snapshot` 子命令验证一遍。它只登录、只执行 `display acl`，不写任何配置：

```bash
/usr/local/bin/aclagent snapshot -config /etc/aclagent/config.json -stream
```

`-stream` 会把整个 telnet 会话逐行打到 stderr，标准输出是一份 JSON 结果。请确认两件事：

1. 登录后的提示符被正确识别（会话没有卡在读取上，也没有超时）
2. `display acl <N>` 的输出完整——最后一条 rule 之后紧跟提示符，中间的 `---- More ----` 分页都被翻完了

第 2 点是有实际后果的那个：规则 ID 按快照里的最大值 +1 分配，读漏了尾部就会分到一个正在生效的 ID 上。写入前的同会话 guard 会拦住这种情况（目标 ID 已存在就中止），所以后果是执行失败而不是覆盖，但值得一次就确认清楚。

跑完后 `journalctl` 或终端里那段会话原文本身就是最有价值的东西：目前的自动化测试跑在一台仿真设备上，它的提示符和分页行为是照 H3C 文档写的，不是照真机抓的。

---

## 安全说明

- 口令是 base64 编码，安全性依赖文件权限 `0400`
- `acl-agent` 只在 Linux 上启动
- `save` 失败不自动回滚，报 `save_failed` 由人决定
- `comment` 失败必须回滚整条规则（仅在 `rule_comment` 打开时有这一步）

---

## 从源码构建

```bash
git clone https://github.com/githubflyideas/acl-edit-only
cd acl-edit-only

CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/aclagent ./cmd/aclagent/
CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/aclweb   ./cmd/aclweb/
```

Go 1.23+，无 CGo 依赖。
