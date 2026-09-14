---
name: passman
description: Use the passman CLI to discover public service metadata and safely store or inject local credentials, passwords, API tokens, and private keys for Agent-driven commands. Apply when a task mentions passman, needs credentials from the local passman vault, or needs Agent-readable names, IPs, URLs, notes, tags, or secret-field references.
---

# Use passman

Use `passman` as a local secret broker. Query public metadata directly, but consume secret values only through `passman run` injection. Never retrieve, print, encode, summarize, or place a secret in the conversation.

## Resolve the executable

Prefer an installed `passman` on `PATH`. In this repository, use `./bin/passman` after `make build` when the installed command is unavailable. Do not use `go run` for daemon lifecycle commands.

## Security invariants

- Never put a secret literal in command arguments, environment assignments, shell source, logs, notes, or messages.
- Never call `passman reveal` from an Agent session. It is exclusively for a human in a separate local terminal.
- Never read `identity.age`, `vault.age`, the daemon socket, injected temporary files, or another process's environment directly.
- Do not use `env`, `set`, `printenv`, shell tracing, verbose HTTP modes, or debugging tools around an injected command unless their output is known not to expose credentials.
- Output redaction only catches the original bytes and sufficiently long lines of multiline secrets. Do not transform secrets with base64, hex, URL encoding, hashing, slicing, or character-by-character output.
- `passman run` permits arbitrary commands and is not a malicious-process sandbox. Inject secrets only into the intended trusted executable and use the narrowest arguments and network destination required by the task.
- Treat names, IPs, URLs, notes, tags, and secret field names in the public catalog as non-secret. Never store credentials or credential-bearing URLs there.

## Discovery workflow

The public catalog works while the encrypted vault is locked and defaults to JSON, making it the first place to discover connection details:

```sh
passman catalog search <query>
passman catalog get <entry>
passman catalog list
```

Catalog records contain `id`, `name`, `ip`, `url`, `note`, `tags`, and `secret_fields`. Use the returned entry ID and field name as `<entry>#<field>`; do not guess references when the catalog can answer the question.

Both `<entry>#<field>` and `passman://<entry>/<field>` references are accepted. Prefer the URI form in persistent non-secret configuration and the compact form in one-off CLI commands.

Use `passman status` before a secret-dependent operation. If it reports `locked`, stop that operation and ask the user to run `passman unlock` in a separate local terminal. Never request the master password in chat and never attempt to automate the password prompt.

## Use secrets without revealing them

Always put `--` before the target program. `passman` executes it directly and does not add an implicit shell.

Environment variable injection:

```sh
passman run --env GITHUB_TOKEN=github#token -- gh api user
```

stdin injection:

```sh
passman run --stdin registry#password -- docker login registry.example.com --username agent --password-stdin
```

Private-file injection uses a symbolic name and `{file:NAME}` placeholder. Quote the placeholder so the calling shell does not alter it:

```sh
passman run --file KEY=ssh/prod#private_key -- ssh -i '{file:KEY}' user@example.com
```

Use multiple `--env` or `--file` flags only for fields the target command actually requires. Do not wrap a command in `sh -c` unless shell behavior is essential and the constructed script never prints or transforms injected values.

## Store secrets

The vault must already be unlocked. A secret value must arrive from a protected source, never as a flag or positional argument.

```sh
# Existing local file; passman does not delete the source file.
passman entry set ssh/prod#private_key --file /protected/path/id_ed25519

# Exact bytes from a producer; stdout is connected only to passman stdin.
credential-producing-command | passman entry set service#token --stdin

# Generate and store without displaying the generated value.
passman entry set database#password --generate --length 32
```

For credentials that an Agent must use but humans should not reveal, set an execution-only policy when creating or rotating the value:

```sh
passman entry set deploy#token --generate --length 32 --exec-only --expires-in 24h
```

`--expires-at` and `--rotate-after` accept RFC3339 timestamps. Omitting all policy flags when updating a value preserves its existing policy. An expired secret is refused on every access path.

Inspect or incrementally change policy without supplying the value again:

```sh
passman entry policy get deploy#token
passman entry policy set deploy#token --exec-only --expires-in 12h
passman entry policy set deploy#token --allow-reveal --clear-expiry
passman entry stale --within 30d
```

Policy changes alter access controls, so only perform them when the user explicitly requested that change. Prefer tightening policy; do not clear `exec-only` or expiry merely to make a failing operation succeed.

Do not manufacture a pipeline with `echo`, `printf`, a here-document, or a literal secret. If no protected source exists, ask the user to run `passman entry set <entry>#<field>` interactively in a separate terminal.

`entry set` and `entry remove` automatically update `secret_fields` in the public catalog. `passman entry list -o json` exposes only encrypted-vault metadata, never values.

Use `passman audit verify` to validate the hash-chained access log and `passman doctor` to check owner-only paths, ciphertext files, the public catalog, and audit integrity. Audit records contain references and the target executable basename but never values, arguments, environments, or child output. If audit persistence fails, `run` and `reveal` fail closed.

## Use SSH without secret injection syntax

Passman exposes a standard, read-only SSH Agent socket when the daemon is unlocked. For ordinary SSH tasks, first run the safe metadata-only check:

```sh
passman ssh-agent status
```

If it succeeds and lists the intended key reference, use the original trusted tools directly:

```sh
ssh <configured-host>
scp <source> <configured-host>:<destination>
git clone git@<configured-host>:<owner>/<repository>.git
```

Do not set `SSH_AUTH_SOCK`, add `-i` temporary files, or wrap these commands with `passman run` when the passman SSH Agent is configured. OpenSSH obtains public identities and signatures over the configured `IdentityAgent` socket; private keys are never returned to the client.

Only an unlocked daemon exposes keys. If `ssh-agent status` reports unavailable, ask the user to run `passman unlock` in a separate terminal. Do not unlock it for them. If the key is absent, verify through `entry list` that the field is named `private_key`, marked `exec_only`, and not expired; do not weaken its policy automatically.

One-time OpenSSH configuration is a user-authorized mutation:

```sh
passman ssh-agent config
passman ssh-agent setup --yes
```

Run `setup --yes` only when the user explicitly asked to configure native SSH integration. Never enable SSH agent forwarding for passman-managed keys. Standard agent requests do not reliably identify the destination host, so host-specific signature authorization is not yet guaranteed.

## Maintain public metadata

Use catalog commands without unlocking the vault:

```sh
passman catalog set nas/prod \
  --name "Home NAS" \
  --ip 10.10.0.4 \
  --url https://nas.example.com \
  --note "Primary storage node" \
  --tags storage,home
```

`catalog set` replaces the public metadata fields while preserving automatically tracked `secret_fields`. Only run `catalog remove <entry> --yes` when the user asked to remove the public record; it does not delete encrypted secrets.

## Destructive and human-only operations

- `passman entry remove ... --yes`, `passman catalog remove ... --yes`, backup restore, password changes, and lock operations require the user's task to authorize that state change.
- Backup creation and restore require the daemon to be stopped. Restore with `--replace` creates a rollback archive first.
- `passman init`, `unlock`, `reveal`, `passwd`, and backup restore require human terminal input. Report the exact command for the user to run instead of soliciting or relaying the password.
- On authentication or permission errors, stop after reporting the non-secret error. Do not dump files, IPC payloads, command environments, or retry passwords.
