After receiving the token, you can verify its working by running `sandbox-cli images`.

The command will display a list of available images in the sandbox.

<!-- termynal -->

```sh
$ sandbox-cli images

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Name                 ┃ ID                  ┃ Version    ┃ Product version ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ astra                │ astralinux-orel-x64 │    ...     │       ...       │
│ ubuntu               │ ubuntu-jammy-x64    │    ...     │       ...       │
│ Windows 10 Pro       │ win10-1803-x64      │    ...     │       ...       │
│ Windows 7 Enterprise │ win7-sp1-x64        │    ...     │       ...       │
└──────────────────────┴─────────────────────┴────────────┴─────────────────┘
```

!!! info "Info"

    The image list may differ from the one shown.

    It all depends on the selected images in the license.

When running with the `-h` flag, you can view the list of available options, in particular the sandboxes specified in the config file.

<!-- termynal -->

```sh
$ sandbox-cli images -h

Usage: sandbox-cli images [OPTIONS]

Get available images in the sandbox.

╭─ Sandbox ─────────────────────────────────────────────────────────────────╮
│ --key  -k  The key to access the sandbox                                  │
│            test-1,test-2,test-3 [default: test-1]                         │
╰───────────────────────────────────────────────────────────────────────────╯
```
