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

Default: `["infected"]`

### `sandbox`

| Option                                  | Description                                                                                                                 | Default |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------- |
| name<span style="color: red">\*</span>  | Custom token name to be used in the parameters when selecting sandboxes.                                                    | `None`  |
| key <span style="color: red">\*</span>  | A token received through the sandbox interface. <br> See how to get it in [Getting started](./tutorial/getting-started.md). | `None`  |
| host <span style="color: red">\*</span> | The IP address or domain where the sandbox is located. <br> Example: `10.10.10.10` or `sandbox.example.com`                 | `None`  |
| max-workers                             | The number of simultaneously running jobs.                                                                                  | `8`     |

!!! note "Note"

    If you specify a higher number of `max-workers`, the performance will not increase, the tasks will just hang in the queue.

#### `ssh`

| Option   | Description                       | Default |
| -------- | --------------------------------- | ------- |
| login    | The user's login on the server    | `None`  |
| password | The user's password on the server | `None`  |

## Full configuration

```toml title="Config example"
# passwords that will be sent to the sandbox for unpacking archives
passwords = ["infected"]

# Specify available sandboxes
# Keep in mind that first sandbox is used by default
# name - short name for the sandbox
# key - token used for the sandbox
# host - host of the sandbox
# max-workers - simultaneously running scans
# ssh username/password - optional params
[[sandbox]]
name = ""
key = ""
host = ""
max-workers = 8
ssh = { username = "", password = "" }

[[sandbox]]
name = ""
key = ""
host = ""
max-workers = 8
```
