# passman

`passman` 是一个供本地 Agent 使用的加密秘密代理。它把密码、Token、私钥等保存在 age 加密保险库中，并让 Agent 通过引用把秘密注入子进程，而不是把明文放进命令参数或普通命令输出。

> [!IMPORTANT]
> `passman run` 允许执行任意命令，因此它防止的是意外泄露，不是恶意 Agent 或恶意子进程。接收秘密的程序仍能编码、分片、写文件或通过网络外传秘密。不要把本工具当作恶意代码沙箱。

## 安装

需要 Go 1.25.10 或更高补丁版本，以及 Linux 或 macOS。较早的 Go 1.25 版本包含本项目会触达的标准库安全漏洞。

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

项目采用手动构造注入；CLI、守护进程、IPC、存储、加密、执行器、遮罩器和备份模块相互隔离。秘密值使用 `[]byte` 传递并在可控位置尽力清零，但 Go 运行时不保证完整的内存零化。
