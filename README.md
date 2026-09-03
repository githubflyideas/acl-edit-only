# acl-edit-only

H3C 交换机 ACL 审批系统。两进程架构：`aclweb`（Web/DB）永远不持有设备口令；`acl-agent`（telnet/口令）每次执行几秒后退出。

操作流程：提交申请 → 看 diff → 确认执行 → 实时看终端输出。

---

## 部署

解压到任意目录，两个二进制和两份配置放在一起就能跑。不需要装到 `/usr/local/bin`，不需要 `/etc`，不需要 `/var/lib`。

```
acl-edit-only/
├── aclweb
├── aclagent
├── aclweb.json
├── aclagent.json
└── credential
```

`aclagent.json` —— 只有四项是必填的：

```json
{
  "acl": 3977,
  "range_min": 2000,
  "range_max": 4999,
  "device_addr": "192.168.1.1:23"
}
```

`aclweb.json` —— 三项必填，`acl` / `range_min` / `range_max` 必须和上面一致：

```json
{
  "listen": "127.0.0.1:8080",
  "acl": 3977,
  "range_min": 2000,
  "range_max": 4999
}
```

`credential` —— 交换机上配了本地用户的，第一行用户名，第二行口令的 base64：

```bash
printf 'admin\n' > credential
printf 'yourpassword' | base64 >> credential
chmod 600 credential
```

交换机上**没有用户名、只认口令**的（登录后直接问 `Password:`），就只写一行 base64：

```bash
printf 'yourpassword' | base64 > credential
chmod 600 credential
```

agent 不猜：一行就是不发送任何用户名。如果设备其实要用户名而文件里只有一行，报的是"设备要用户名而 credential 只有口令"，不是一句登录被拒。

只有这个文件有权限要求：不能被别人读，且属主是跑 aclagent 的那个用户。

启动：

```bash
./aclweb
```

没填的东西都取配置文件所在目录里的同名默认值：数据库 `aclweb.db`、plan 目录 `plans/`（自动创建）、agent 配置 `aclagent.json`、agent 二进制取 `aclweb` 旁边的 `aclagent`、agent 状态文件 `agent-state.json`。配置里写相对路径时，是相对配置文件自己所在的目录解析的，不是相对启动时的工作目录——所以整个目录可以随便搬。

想放到别处的，写绝对路径就行，绝对路径不会被改写。

### 可选配置

| 字段 | 位置 | 默认 | 说明 |
|---|---|---|---|
| `alloc_max` | 两边 | = `range_max` | 自动分配上限，可在范围顶部留出保留区 |
| `rule_comment` | aclweb | `false` | 是否在每条规则下写一行 `rule <N> comment ACLSYS-REQ-...` |
| `tls_cert` / `tls_key` | aclweb | 无 | 填了就走 HTTPS，不填是明文 HTTP |
| `daily_limit` | aclagent | 50 | 每日写入次数上限 |
| `connect_timeout_s` / `read_timeout_s` | aclagent | 10 / 30 | telnet 超时 |
| `reconcile_interval_min` | aclweb | 0（关） | 定时对账间隔 |

### 先在本机试一遍

发布包里带了一个 `fakesw`，是个真的 telnet 服务端，装成 H3C 的样子（IAC 协商、版权 banner、`---- More ----` 分页、命令回显、`display acl` 的真实格式）。测试套件就跑在它上面。把 `device_addr` 指向它，整个流程可以在一台机器上走完，附近没有任何交换机：

```bash
./fakesw &                      # 监听 127.0.0.1:2300，登录 aclbot/aclbot-pw
./aclweb
```

对应的 `aclagent.json` 改一行：`"device_addr": "127.0.0.1:2300"`，`credential` 写 `aclbot` 和 `aclbot-pw` 的 base64。

`fakesw -user ""` 是只认口令、不问用户名的模式，用来对着单行 credential 试。

### systemd（想做成服务的话）

```ini
[Unit]
Description=H3C ACL Approval Web
After=network.target

[Service]
WorkingDirectory=/opt/acl-edit-only
ExecStart=/opt/acl-edit-only/aclweb
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

这一行走的是 **stderr**，而且只在数据库里还没有用户时打印一次。用 `./aclweb >aclweb.log` 只重定向 stdout 是看不到它的：

```bash
./aclweb >aclweb.log 2>&1            # 或者
journalctl -u aclweb | grep "INITIAL ADMIN"
```

密码丢了不用删库，让它重新发一个：

```bash
./aclweb -reset-password admin
```

这条命令重置密码、吊销该用户所有会话、打印新密码后退出。它不校验旧密码——能运行它的人已经能读数据库文件了。

访问配置里 `listen` 的地址（没填 `tls_cert` 时是明文 HTTP），登录后立即改密。

---

## 操作流程

1. **提交申请** — 填写目的 IP、端口、协议、原因
2. **看变更对比** — 系统从设备抓快照，左右两栏并排显示"现在"和"执行后"，改动的行两边对齐、各带 `-` / `+` 标记，未变更的长段落折叠成一行；留档用的原始 unified diff 在下面折叠着，哈希算的是它
3. **确认执行** — 核对无误后点击，页面展开终端窗口，实时显示 telnet 连接和命令执行过程。终端输出不会自动消失，看完了自己点刷新（也可以一键复制）
4. **自动验证** — 回读设备，断言规则条数 +1、新规则存在、其余规则未变
5. 成功 → `active`；失败自动回滚 → `dispatch_failed`；回滚也失败 → `inconsistent`（需人工介入）

删除规则走同样的流程（在 active 规则详情页申请删除）。

---

## 对真机做只读验证

在把 Web 端接到生产交换机之前，先用 agent 的 `snapshot` 子命令验证一遍。它只登录、只执行 `display acl`，不写任何配置：

```bash
./aclagent snapshot -stream
```

`-stream` 会把整个 telnet 会话逐行打到 stderr，标准输出是一份 JSON 结果。请确认两件事：

1. 登录后的提示符被正确识别（会话没有卡在读取上，也没有超时）
2. `display acl <N>` 的输出完整——最后一条 rule 之后紧跟提示符，中间的 `---- More ----` 分页都被翻完了

第 2 点是有实际后果的那个：规则 ID 按快照里的最大值 +1 分配，读漏了尾部就会分到一个正在生效的 ID 上。写入前的同会话 guard 会拦住这种情况（目标 ID 已存在就中止），所以后果是执行失败而不是覆盖，但值得一次就确认清楚。

跑完后 `journalctl` 或终端里那段会话原文本身就是最有价值的东西：目前的自动化测试跑在一台仿真设备上，它的提示符和分页行为是照 H3C 文档写的，不是照真机抓的。

---

## 安全说明

- 口令是 base64 编码而非加密，安全性依赖两点：`credential` 文件不可被他人读取且属主是运行进程的用户，以及口令只在几秒钟的 agent 进程里存在
- 只有 `credential` 有权限要求，配置文件不含机密，不做检查
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
CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/fakesw  ./cmd/fakesw/
```

Go 1.23+，无 CGo 依赖。
