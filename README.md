# passman

[中文](#中文) | [English](#english)

<a id="中文"></a>

## 中文

`passman` 是一个供本地 Agent 使用的加密秘密代理。它把密码、Token、私钥等保存在 age 加密保险库中，并让 Agent 通过引用把秘密注入子进程，而不是把明文放进命令参数或普通命令输出。

> [!IMPORTANT]
> `passman run` 允许执行任意命令，因此它防止的是意外泄露，不是恶意 Agent 或恶意子进程。接收秘密的程序仍能编码、分片、写文件或通过网络外传秘密。不要把本工具当作恶意代码沙箱。

## 安装

需要 Go 1.25.13 或更高补丁版本，以及 Linux 或 macOS。较早的 Go 1.25 版本包含本项目会触达的标准库安全漏洞。

```sh
make build
install -m 0755 bin/passman "$HOME/.local/bin/passman"
```

默认数据目录为系统用户配置目录下的 `passman`。测试或隔离环境可设置非敏感变量 `PASSMAN_HOME`。Linux 优先把 Socket 放在 `$XDG_RUNTIME_DIR/passman`，其他环境使用仅当前 UID 可访问的临时目录。

## 快速开始

初始化和解锁必须由用户在本地终端完成：

```sh
passman init
passman unlock                 # 一直解锁到 passman lock
passman unlock --ttl 30m       # 可选绝对超时
```

秘密值不能作为参数传入：

```sh
# 交互隐藏输入
passman entry set github#token

# Agent 可把已有秘密文件交给 passman，文件内容不会出现在 argv
passman entry set ssh/prod#private_key --file ./id_ed25519

# 管道按原始字节保存，不自动去掉换行
secret-producing-command | passman entry set service#password --stdin

# 生成后直接保存，只报告成功，不显示生成值
passman entry set database#password --generate --length 32

# 只能通过 run 使用，禁止 reveal；也可设置失效和轮换提醒时间
passman entry set deploy#token --generate --exec-only \
  --expires-in 24h \
  --rotate-after 2026-10-01T00:00:00Z
```

设置过策略的秘密会在 `entry list` 元数据中显示 `exec_only`、`expires_at`、
`rotate_after`、`expired` 和 `rotation_due`。失效秘密在 `run` 与 `reveal` 等所有
路径上都会被拒绝；更新秘密时未传策略参数会保留已有策略。

策略可以独立调整而无需重新输入秘密：

```sh
passman entry policy get deploy#token
passman entry policy set deploy#token --exec-only --expires-in 12h
passman entry policy set deploy#token --allow-reveal --clear-expiry
passman entry policy set deploy#token --rotate-after 2026-12-01T00:00:00Z
passman entry policy set deploy#token --clear-rotation

# 默认仅列出已经失效或到达轮换日期的字段
passman entry stale
passman entry stale --within 30d
```

Agent 查看元数据和使用秘密：

```sh
passman entry list -o json

passman run --env GITHUB_TOKEN=github#token -- gh api user

passman run \
  --file KEY=ssh/prod#private_key \
  -- ssh -i '{file:KEY}' user@example.com

passman run --stdin database#password -- some-command --password-stdin
```

## 原生 OpenSSH 集成

passman daemon 同时提供标准 SSH Agent socket。配置一次后，`ssh`、`scp`、
`sftp`、`rsync` 和 Git SSH 都可以继续使用原始命令，不需要 `passman run`、
`SSH_AUTH_SOCK` 或临时私钥文件：

```sh
# 私钥字段必须命名为 private_key，并设置 exec-only 才会提供给 SSH Agent
passman entry set ssh/lihongjie#private_key \
  --file ~/.ssh/lihongjie \
  --exec-only

# 查看将写入的 OpenSSH 配置；确认后执行一次 setup
passman ssh-agent config
passman ssh-agent setup --yes

passman unlock --ttl 8h
passman ssh-agent status

ssh fnos-nas
scp ./file fnos-nas:/tmp/
git clone git@github.com:owner/repository.git
```

`setup` 创建 owner-only 的 `~/.ssh/passman-agent.conf`，并在现有
`~/.ssh/config` 顶部幂等加入一条 `Include`。OpenSSH 的 `IdentityAgent`
直接指向 `~/.config/passman/ssh-agent.sock`，因此会覆盖对
`SSH_AUTH_SOCK` 的需求。原有 Host、Hostname、User、Port、ProxyJump 和
known_hosts 配置保持由 OpenSSH 管理。

SSH Agent 只开放列出公钥和签名，拒绝远程协议添加、删除、锁定或导入密钥。
每次签名进入 passman 审计链。锁定保险库、TTL 到期或 daemon 退出时 socket
同时关闭。当前版本只加载未额外使用 passphrase 加密、字段名为
`private_key`、策略为 `exec-only` 且未过期的 OpenSSH/PEM 私钥；解析失败的
字段不会暴露给 SSH 客户端。

> [!WARNING]
> 不要开启 SSH agent forwarding（`ForwardAgent yes`）。标准 SSH Agent
> 签名请求通常不包含最终目标主机，第一版无法按目标 Host 限制签名授权。

除兼容的 `entry#field` 外，也支持便于配置文件保存的 URI 引用。以下引用等价：

```text
ssh/prod#private_key
passman://ssh/prod/private_key
passman://ssh/prod#private_key
```

每次允许或拒绝 `run`/人工 `reveal` 都会写入 owner-only 的哈希链审计日志；
审计写入或校验失败时拒绝返回秘密：

```sh
passman audit list
passman audit verify
passman doctor
```

审计只记录秘密引用、动作、时间和目标程序 basename，不记录秘密值、参数、环境
变量或子进程输出。`doctor` 检查数据目录、密文文件、公开目录和审计链的基本安全
属性，并支持 JSON 输出供 Agent 判断。

## Agent 可查询的公开目录

名称、IP、URL、备注和标签保存在独立的明文 `catalog.json` 中，不需要解锁即可查询。秘密字段名会在 `entry set/remove` 后自动同步，但字段值仍只存在加密保险库中。

```sh
passman catalog set nas/prod \
  --name "家庭 NAS" \
  --ip 10.10.0.4 \
  --url https://nas.example.com \
  --note "主要存储节点，不要在此填写密码" \
  --tags storage,home

passman catalog get nas/prod
passman catalog list
passman catalog search storage
```

查询默认输出 JSON，也可使用 `-o table`。这些字段明确不加密，不要在名称、URL、备注或标签中写入账号密码、Token、私钥或带凭据的 URL。加密备份会同时包含这份公开目录；目录内容在备份中仍属于明文元数据。

`run` 不会隐式启动 shell。只有显式写出 `sh -c` 时才会进行 shell 展开。注入文件放在一次性 0700 目录中，文件权限为 0600，并在子进程结束后清理。

人工查看要求重新输入主密码，并只写 `/dev/tty`：

```sh
# 只能在 Agent 会话之外的本地终端执行
passman reveal github#token
```

锁定会终止守护进程，让操作系统回收其中的身份和保险库明文：

```sh
passman lock
```

## 加密备份

备份和恢复要求保险库处于锁定状态。身份和秘密保险库保持密文，公开目录按其明文属性一并归档：

```sh
passman backup create --output passman-2026-09-11.pmbak
passman backup restore --input passman-2026-09-11.pmbak
passman backup restore --input backup.pmbak --replace
```

`--replace` 会先在数据目录创建一个加密 rollback 备份。忘记主密码后无法恢复数据。

## 安全边界

`passman` 提供：

- age 加密的静态保险库和口令加密身份文件；
- 0700 目录、0600 文件与同 UID Unix Socket 校验；
- 避免秘密进入命令参数；
- 对子进程 stdout/stderr 中完整秘密及私钥多行片段进行跨分块遮罩；
- 对 IPC、字段大小、归档成员和路径进行限制；
- 主密码变更、显式锁定和可选 TTL。
- 字段级 exec-only、失效时间与轮换提醒元数据；
- fail-closed 的哈希链访问审计和本地安全自检。
- 标准、只读的 SSH Agent 协议集成，私钥只在 daemon 内参与签名。

`passman` 不防御：

- root、同 UID 的 ptrace/进程内存检查、系统被攻陷；
- swap、休眠镜像或平台崩溃转储中的内存内容；
- 子进程对秘密做 base64、hex、URL 编码、分片或其他转换；
- 子进程把秘密写入其他文件、日志或网络；
- Agent 显式调用 `sh -c` 构造外传命令。

因此只把秘密注入你信任的程序，并尽量限定该程序的参数和网络目标。若需要抵御恶意 Agent，应在后续版本采用人工批准的动作模板和操作系统沙箱，而不是任意命令模式。

## 开发

```sh
make test
make race
make lint
make security
```

## Agent Skill

仓库内置 [`passman` skill](.agents/skills/passman/SKILL.md)，支持 Agent 自动发现安全查询、存储和注入流程。支持项目级 skill 的 Agent 克隆仓库后即可使用；也可以安装到用户目录：

```sh
mkdir -p "$HOME/.agents/skills"
cp -R .agents/skills/passman "$HOME/.agents/skills/passman"
```

项目采用手动构造注入；CLI、守护进程、IPC、存储、加密、执行器、遮罩器和备份模块相互隔离。秘密值使用 `[]byte` 传递并在可控位置尽力清零，但 Go 运行时不保证完整的内存零化。

---

<a id="english"></a>

## English

`passman` is an encrypted secret broker for local Agents. It stores passwords,
tokens, private keys, and other sensitive values in an age-encrypted vault. An
Agent injects secrets into child processes by reference, so plaintext does not
need to appear in command-line arguments or normal command output.

> [!IMPORTANT]
> `passman run` can execute arbitrary commands. It prevents accidental disclosure;
> it is not a sandbox for a malicious Agent or child process. A process that
> receives a secret can still encode it, split it, write it to disk, or send it
> over the network.

### Installation

passman requires Go 1.25.13 or a later patch release and supports Linux and
macOS. Earlier Go 1.25 releases contain a standard-library vulnerability reached
by this project.

```sh
make build
install -m 0755 bin/passman "$HOME/.local/bin/passman"
```

The default data directory is the `passman` directory under the current user's
system configuration directory. Set the non-sensitive `PASSMAN_HOME` variable
for tests or isolated environments. On Linux, the socket is placed under
`$XDG_RUNTIME_DIR/passman` when available; other environments use a temporary
directory accessible only by the current UID.

### Quick start

Initialization and unlocking must be performed by the user in a local terminal:

```sh
passman init
passman unlock                 # Remain unlocked until passman lock
passman unlock --ttl 30m       # Optional absolute timeout
```

Never pass a secret value as a command-line argument:

```sh
# Hidden interactive input
passman entry set github#token

# An Agent may pass an existing secret file without placing its contents in argv
passman entry set ssh/prod#private_key --file ./id_ed25519

# Standard input is stored byte-for-byte; trailing newlines are not removed
secret-producing-command | passman entry set service#password --stdin

# Generate and store a value without displaying it
passman entry set database#password --generate --length 32

# Restrict a secret to run, with optional expiry and rotation reminders
passman entry set deploy#token --generate --exec-only \
  --expires-in 24h \
  --rotate-after 2026-10-01T00:00:00Z
```

Policy metadata appears in `entry list` as `exec_only`, `expires_at`,
`rotate_after`, `expired`, and `rotation_due`. Expired secrets are denied on all
paths, including `run` and `reveal`. Updating a value without policy flags
preserves its existing policy.

Policies can be changed without entering the secret again:

```sh
passman entry policy get deploy#token
passman entry policy set deploy#token --exec-only --expires-in 12h
passman entry policy set deploy#token --allow-reveal --clear-expiry
passman entry policy set deploy#token --rotate-after 2026-12-01T00:00:00Z
passman entry policy set deploy#token --clear-rotation

# Show expired fields or fields whose rotation date has arrived
passman entry stale
passman entry stale --within 30d
```

Agents can inspect metadata and inject secrets as follows:

```sh
passman entry list -o json

passman run --env GITHUB_TOKEN=github#token -- gh api user

passman run \
  --file KEY=ssh/prod#private_key \
  -- ssh -i '{file:KEY}' user@example.com

passman run --stdin database#password -- some-command --password-stdin
```

### Native OpenSSH integration

The passman daemon also provides a standard SSH Agent socket. After one-time
configuration, the original `ssh`, `scp`, `sftp`, `rsync`, and Git SSH commands
work without `passman run`, `SSH_AUTH_SOCK`, or temporary private-key files:

```sh
# The field must be named private_key and marked exec-only
passman entry set ssh/lihongjie#private_key \
  --file ~/.ssh/lihongjie \
  --exec-only

# Preview the OpenSSH configuration, then apply it once
passman ssh-agent config
passman ssh-agent setup --yes

passman unlock --ttl 8h
passman ssh-agent status

ssh fnos-nas
scp ./file fnos-nas:/tmp/
git clone git@github.com:owner/repository.git
```

`setup` creates the owner-only `~/.ssh/passman-agent.conf` file and idempotently
adds an `Include` at the top of the existing `~/.ssh/config`. OpenSSH's
`IdentityAgent` points directly to `~/.config/passman/ssh-agent.sock`, removing
the need for `SSH_AUTH_SOCK`. OpenSSH continues to manage existing `Host`,
`Hostname`, `User`, `Port`, `ProxyJump`, and known-hosts settings.

The SSH Agent exposes only public-key listing and signing. Protocol requests to
add, remove, lock, or import keys are rejected, and each signature is recorded
in the passman audit chain. Locking the vault, reaching the unlock TTL, or
stopping the daemon also closes the socket. The current release loads only
unexpired OpenSSH or PEM keys whose field is named `private_key`, whose policy is
`exec-only`, and which are not additionally protected by a passphrase. Fields
that cannot be parsed are not exposed to SSH clients.

> [!WARNING]
> Do not enable SSH Agent forwarding (`ForwardAgent yes`). Standard SSH Agent
> signing requests normally omit the final destination host, so this release
> cannot restrict signing authorization by target host.

In addition to the compatible `entry#field` form, configuration files can use
URI references. These references are equivalent:

```text
ssh/prod#private_key
passman://ssh/prod/private_key
passman://ssh/prod#private_key
```

Every allowed or denied `run` or manual `reveal` request is written to an
owner-only hash-chain audit log. If audit writing or verification fails, passman
refuses to return the secret:

```sh
passman audit list
passman audit verify
passman doctor
```

Audit events contain the secret reference, action, timestamp, and target program
basename. They do not contain secret values, arguments, environment variables,
or child-process output. `doctor` checks the basic security properties of the
data directory, encrypted files, public catalog, and audit chain. It also
supports JSON output for Agents.

### Public metadata catalog for Agents

Names, IP addresses, URLs, notes, and tags are stored separately in plaintext
`catalog.json`, so Agents can query them without unlocking the vault. Secret
field names are synchronized after `entry set` and `entry remove`, but values
remain only in the encrypted vault.

```sh
passman catalog set nas/prod \
  --name "Home NAS" \
  --ip 10.10.0.4 \
  --url https://nas.example.com \
  --note "Primary storage node; never put passwords here" \
  --tags storage,home

passman catalog get nas/prod
passman catalog list
passman catalog search storage
```

Catalog queries return JSON by default and support `-o table`. Catalog fields
are intentionally unencrypted: never store passwords, tokens, private keys, or
credential-bearing URLs in names, URLs, notes, or tags. Encrypted backups include
the catalog, but the catalog remains plaintext metadata inside the archive.

`run` never starts a shell implicitly. Shell expansion occurs only when a command
explicitly invokes `sh -c`. Injected files are created in a one-use 0700
directory with mode 0600 and removed when the child process exits.

Manual viewing requires the master password again and writes only to `/dev/tty`:

```sh
# Run only in a local terminal outside an Agent session
passman reveal github#token
```

Locking terminates the daemon so the operating system can reclaim its in-memory
identity and decrypted vault data:

```sh
passman lock
```

### Encrypted backup

The vault must be locked before backup or restore. The identity and secret vault
remain encrypted; the public catalog is archived according to its plaintext
design:

```sh
passman backup create --output passman-2026-09-11.pmbak
passman backup restore --input passman-2026-09-11.pmbak
passman backup restore --input backup.pmbak --replace
```

`--replace` first creates an encrypted rollback backup in the data directory.
Data cannot be recovered if the master password is lost.

### Security boundaries

passman provides:

- an age-encrypted vault and a password-encrypted identity file;
- 0700 directories, 0600 files, and same-UID Unix socket verification;
- secret injection without placing values in command-line arguments;
- cross-chunk redaction of complete secrets and multiline private-key fragments
  from child-process stdout and stderr;
- limits on IPC messages, field sizes, archive members, and paths;
- master-password changes, explicit locking, and optional unlock TTLs;
- field-level exec-only, expiry, and rotation-reminder metadata;
- fail-closed hash-chain access auditing and local security diagnostics; and
- a standard read-only SSH Agent integration in which private keys sign only
  inside the daemon.

passman does not defend against:

- root, same-UID ptrace or process-memory inspection, or a compromised system;
- memory copied into swap, hibernation images, or platform crash dumps;
- child processes encoding, splitting, or otherwise transforming secrets;
- child processes writing secrets to other files, logs, or networks; or
- an Agent explicitly invoking `sh -c` to construct an exfiltration command.

Inject secrets only into programs you trust, and constrain their arguments and
network destinations whenever possible. Defending against a malicious Agent
requires user-approved action templates and operating-system sandboxing rather
than unrestricted command execution.

### Development

```sh
make test
make race
make lint
make security
```

### Agent Skill

The repository includes a [`passman` skill](.agents/skills/passman/SKILL.md) that
teaches Agents the safe discovery, storage, and injection workflows. Agents that
support project-level skills can use it directly after cloning the repository.
It can also be installed in the user skill directory:

```sh
mkdir -p "$HOME/.agents/skills"
cp -R .agents/skills/passman "$HOME/.agents/skills/passman"
```

The project uses manually constructed dependency injection. The CLI, daemon,
IPC, storage, cryptography, executor, redactor, and backup modules are isolated
from each other. Secret values are passed as `[]byte` and cleared where
practical, but the Go runtime cannot guarantee complete memory zeroization.
