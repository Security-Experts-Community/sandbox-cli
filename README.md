![Image](https://raw.githubusercontent.com/Security-Experts-Community/sandbox-cli/refs/heads/main/docs/assets/logo_with_text.svg)

<p align="center">
    <em>Work with PT Sandbox like a pro</em>
</p>

---

**Documentation**: <a href="https://security-experts-community.github.io/sandbox-cli">https://security-experts-community.github.io/sandbox-cli</a>

**Source Code**: <a href="https://github.com/Security-Experts-Community/sandbox-cli">https://github.com/Security-Experts-Community/sandbox-cli</a>

---

> [!NOTE]
> `python >= 3.11` is required.

## Installation

Using `pipx`:

```sh
pipx install sandbox-cli
```

Using `PyPi`:

```sh
pip install sandbox-cli
```

NixOS:

```sh
nix shell 'github:Security-Experts-Community/sandbox-cli'
```

### Config

You must create default config file as described in `docs/config-examples/config.toml`:

Linux/MacOS:

```sh
~/.config/sandbox-cli/config.toml
or
$XDG_HOME_CONFIG_HOME/sandbox-cli/config.toml
```

Windows:

```ps1
%APPDATA%\sandbox-cli\config.toml
```

## Available options

- `scanner` - Scan with the sandbox.
- `images` - Get available images in the sandbox.
- `download` - Download any artifact from the sandbox.
- `email` - Upload an email and get its headers.
- `report` - Generate short report from sandbox scans.
- `unpack`/`conv` - Convert sandbox logs into an analysis-friendly format.
- `rules` - Working with raw sandbox rules.

<p align="middle">
    <img width="50%" src="https://raw.githubusercontent.com/Security-Experts-Community/sandbox-cli/refs/heads/main/docs/assets/pic_right.svg">
</p>

## Usage examples

### images

Get all availables images:

```bash
sandbox-cli images
```

```bash
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Name                  ┃ ID                      ┃ Version    ┃ Product version ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ altlinux              │ altworkstation-10-x64   │ ...        │ ...             │
│ astra                 │ astralinux-smolensk-x64 │ ...        │ ...             │
│ redos                 │ redos-murom-x64         │ ...        │ ...             │
│ ubuntu                │ ubuntu-jammy-x64        │ ...        │ ...             │
│ Windows 10 Pro        │ win10-1803-x64          │ ...        │ ...             │
│ Windows 10 Enterprise │ win10-22H2-x64          │ ...        │ ...             │
│ Windows 10 Pro        │ win11-23H2-x64          │ ...        │ ...             │
│ Windows 7 Enterprise  │ win7-sp1-x64            │ ...        │ ...             │
│ Windows 7 Enterprise  │ win7-sp1-x64-ics        │ ...        │ ...             │
└───────────────────────┴─────────────────────────┴────────────┴─────────────────┘
```

### scanner

Scan the file on all available windows images with timeout 60s and with automatic logs unpacking:

```bash
sandbox-cli scanner scan-new -i windows -t 60 -U malware.exe
```

<p align="middle">
    <img width="50%" src="https://raw.githubusercontent.com/Security-Experts-Community/sandbox-cli/refs/heads/main/docs/assets/pic_left.svg">
</p>

## Development

`uv` is used to build the project.

```bash
uv sync
```
