The utility is configured via a `toml` file.

!!! note "Note"

    If no sandbox is specified, the functions related to interacting with the sandbox will be unavailable.

## Location

=== "Linux / MacOS"

    ```sh
    ~/.config/sandbox-cli/config.toml
    or
    $XDG_CONFIG_HOME/sandbox-cli/config.toml
    ```

=== "Windows"

    ```ps1
    %APPDATA%\sandbox-cli\config.toml
    ```

## Config

### `passwords`

There is often a need to scan various password-protected zip archives.

Here you can specify a list of frequently used passwords that the `sandbox-cli` will send to the sandbox for automatic unpacking.

Default: `["infected", "311138", "password", "12345678", "P@ssw0rd!"]`

### `sandbox`

| Option                                  | Description                                                                                                                 | Default |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------- |
| name<span style="color: red">\*</span>  | Custom token name to be used in the parameters when selecting sandboxes.                                                    | `None`  |
| key <span style="color: red">\*</span>  | A token received through the sandbox interface. <br> See how to get it in [Getting started](./tutorial/getting-started.md). | `None`  |
| host <span style="color: red">\*</span> | The IP address or domain where the sandbox is located. <br> Example: `10.10.10.10` or `sandbox.example.com`                 | `None`  |
| max-workers                             | The number of simultaneously running jobs.                                                                                  | `8`     |
| description                             | Optional description for the sandbox key.                                                                                    | `None`  |

!!! note "Note"

    If you specify a higher number of `max-workers`, the performance will not increase, the tasks will just hang in the queue.

#### `ssh`

| Option   | Description                       | Default |
| -------- | --------------------------------- | ------- |
| username | The user's login on the server    | `None`  |
| password | The user's password on the server | `None`  |

#### `browser`

Here you can specify custom browser to use for opening the analysis links.

| Option   | Description                       | Default |
| -------- | --------------------------------- | ------- |
| path     | Path to custom browser            | `None`  |
| args     | Args to start the browser with    | `None`  |

!!! note "Note"

    Every argument must be in separate string.

### `rules-path`

Base path to the rules directory. When set, `--rules` can be specified as a relative path.

Default: `None`

## Secrets

`key`, `ssh.password` and `docker.token` accept a plain string or a reference to a secret stored elsewhere:

```toml
[[sandbox]]
name = "staging"
host = "sandbox.example.com"
key = { command = "pass show sandbox/staging" }   # stdout of a shell command
# key = { env = "SANDBOX_STAGING_KEY" }           # an environment variable
# key = "plain token"                              # a plain string
```

A reference is resolved only when a command needs that secret, so `--help` or commands for other sandboxes don't run the command. The trailing newline of the command output is stripped.

## Environment variables

| Variable                    | Description                                                                                       |
| --------------------------- | ------------------------------------------------------------------------------------------------- |
| `DEBUG`                     | Show the full traceback on unexpected errors                                                      |
| `SANDBOX_CLI_TERM_PROGRESS` | `1`/`0` — force the native terminal progress indicator (`OSC 9;4`) on/off. Auto-detected by default |
| `SANDBOX_CLI_SYNC_OUTPUT`   | `1`/`0` — force synchronized output (no flickering) on/off. Enabled for terminals by default      |

The progress indicator is shown in the tab bar / taskbar of terminals that support it: Ghostty, WezTerm, Windows Terminal, iTerm2 ≥ 3.6.6, VTE-based terminals, mintty and ConEmu. Inside tmux it works with tmux 3.8 or newer when the outer terminal supports it (`progressbar` in `tmux display -p '#{client_termfeatures}'`); it is disabled inside screen and zellij.

## Full configuration

```toml title="Config example"
# passwords that will be sent to the sandbox for unpacking archives
passwords = ["infected", "311138", "password", "12345678", "P@ssw0rd!"]

# Base path to the rules directory (optional)
# rules-path = "/path/to/rules"

# Use this section only if you don't want to use your default browser
# or it works incorrectly
# [browser]
# path to your browser
# path = "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
# args to run your browser with
# args = ["-new-tab"]

# Specify available sandboxes
# Keep in mind that first sandbox is used by default
# name - short name for the sandbox
# key - token used for the sandbox
# host - host of the sandbox
# max-workers - simultaneously running scans
# description - optional description
# ssh username/password - optional params
[[sandbox]]
name = ""
key = ""
host = ""
max-workers = 8
description = ""
ssh = { username = "", password = "" }

[[sandbox]]
name = ""
key = ""
host = ""
max-workers = 8
```
