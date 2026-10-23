# Config

`~/.config/sandbox-cli/config.toml` (`$XDG_CONFIG_HOME/sandbox-cli/config.toml`,
`%APPDATA%\sandbox-cli\config.toml` on Windows). Never print it or copy keys from it:
read only the names you need (`name`, `host`).

```toml
# archive passwords, used by `scan-new -ua`, `scanner scan` and `re-scan`
passwords = ["infected", "311138", "password", "12345678", "P@ssw0rd!"]

# base folder for the -r windows / -r linux aliases
rules-path = "~/rules"

# the first [[sandbox]] is the default --key and the host for remote rule compilation
[[sandbox]]
name = "main"                                  # used with --key
host = "sandbox.example.com"
key = { command = "pass show sandbox/main" }   # or { env = "SANDBOX_MAIN_KEY" } or a plain string
max-workers = 8                                # tasks running at once per command
description = "production"
ssh = { username = "user", password = { env = "SANDBOX_SSH_PASSWORD" } }   # remote rule compilation

[[sandbox]]
name = "staging"
host = "sandbox-staging.example.com"
key = "<api token>"

# local rule compilation with -l
[docker]
registry = "registry.example.com"
image-name = "sandbox/package-builder"
image-tag = "latest"
username = "user"
token = { env = "REGISTRY_TOKEN" }

# only if the default browser doesn't open links
[browser]
path = "/usr/bin/firefox"
args = ["-new-tab"]
```

## Secrets

`key`, `ssh.password` and `docker.token` take a plain string, `{ env = "NAME" }` or
`{ command = "shell command" }` (stdout without the trailing newline). The CLI resolves a
reference only when a command needs that secret.

## Environment variables

| Variable | Effect |
| --- | --- |
| `DEBUG=1` | Full traceback on unexpected errors |
| `SANDBOX_CLI_TERM_PROGRESS=0/1` | Force the terminal tab/taskbar progress indicator off or on |
| `SANDBOX_CLI_SYNC_OUTPUT=0/1` | Force synchronized output (flicker-free progress) off or on |
| `XDG_CONFIG_HOME` / `APPDATA` | Where the config is looked up |

## No config yet

`sandbox-cli --help` says *"To access other commands, specify at least one sandbox in the
config"*. Ask the user for the sandbox host and an API token (created in the sandbox web UI
under access tokens) and help them write the file. Don't invent hosts or tokens.
