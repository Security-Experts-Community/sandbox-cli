# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0

### Breaking changes

Every flag now has one meaning across all commands:

| Command | Before | Now |
| --- | --- | --- |
| `scan`, `scan-new` | `--crashdumps -c` | `--crashdumps -C` |
| `re-scan` | `--timeout -t` (response waiting time) | `--wait-timeout -W` |
| `download` | `--logs -l` | `--logs -L` |
| `download` | `--sample -s` | `--sample -sa` |
| `report` | `--suspicious -s` | `--suspicious -su` |
| `images` | `--all -a` | `--all-keys -ak` |
| `completion` | `--install -i` | `--install -I` |
| `rules compile` | `OUT` positional or `--out` | `--out -o` only |
| `rules test` | `RULES` positional or `--rules -r` | positional `RULES_DIR` only |

- `re-scan` accepts all download options of `scan-new` (`-a`, `-A`, `-f`, `-C`, `-p`, `-am`, `-dx`, `-D`), not only `--debug`
- `rules compile` accepts the `windows`/`linux` aliases like the scan commands
- `download`, `email`, `images` and `report` show `--key` under "Sandbox Options"; `report --key` is validated
- `--timeout` (analysis duration) and `--bootkitmon-duration` require at least 10 seconds, as the sandbox does
- `scan` uses the same progress display as `scan-new`

### Added

- Native terminal progress indicator (`OSC 9;4`) for scans, re-scans, downloads and other long operations in Ghostty, WezTerm, Windows Terminal, iTerm2 ≥ 3.6.6, VTE-based terminals, mintty and ConEmu, also inside tmux 3.8+; it turns red when an error occurs
- Synchronized output (DEC mode 2026) for progress displays, which removes flickering in fast terminals (e.g. Ghostty with an unfocused window)
- `SANDBOX_CLI_TERM_PROGRESS` and `SANDBOX_CLI_SYNC_OUTPUT` environment variables to force these features on/off
- `--unpack-archives / -ua` for `scan-new`: archives go through the full scan, which unpacks them with the `passwords` from the config and analyzes every extracted file; each extracted file gets its own result folder (`<image>/<file>/`)
- `--procdump-excludes / -pe` option for `scan-new`: a file with regular expressions of process paths excluded from process dumps (like `--fileextractor-excludes`)
- `key`, `ssh.password` and `docker.token` in the config accept `{ env = "..." }` and `{ command = "..." }` besides plain strings
- `--json / -J` for `scan-new`, `scan`, `re-scan`, `download`, `email`, `images` and `report`: results as JSON lines on stdout, messages and progress on stderr
- `[DONE]`/`[ERROR]` line per task for `download` and `email`
- With `--json` a command-level error is printed as `{"status": "error", "reason": "…"}` on stdout as well

### Changed

- Faster startup: `--help`, `--version` and shell completion no longer import the sandbox API client
- Errors exit with a non-zero status code; a failed task, sandbox or email no longer aborts the others, and the command exits with 1 after the rest finished
- Mistakes are reported before anything is uploaded: missing hook, exclude and extra files, invalid DLL hooks (with `file:line`), `--outbound-connections` values that aren't IP addresses, a missing `--rules` folder, `-l` without the `[docker]` section, re-scan traces without `drakvuf-trace`/`tcpdump.pcap`, invalid task ids and links in `download`, a missing `report` folder
- `report` skips unreadable `report.json` files with an error instead of aborting
- Logs are unpacked in parallel processes when several images are scanned with `--unpack`
- Unpacking uses constant memory instead of loading whole logs, and moves the original files to `raw/` instead of copying them
- `download` opens one connection per sandbox and `--concurrency` limits all downloads together
- `download` accepts task links without `https://`, with a port or query string, and matches the link host to the config `host` ignoring case and port
- `re-scan` extracts `sandbox_logs.zip` to a temporary directory instead of reading the trace into memory
- Output is not wrapped when stdout is not a terminal, so task links stay on one line
- Bumped `cyclopts` to 4.25.3 (the version in nixos-unstable)
- Dropped the `colorama` dependency (rich handles the Windows console itself)
- Migrated git hooks from pre-commit to [prek](https://prek.j178.dev) (`prek.toml`); mypy runs from the locked environment
- ruff is the only formatter and import sorter (black and isort removed)

### Fixed

- `scan-new` ran archives as a single file and ignored the `passwords` from the config; it now warns and suggests `--unpack-archives`
- Results of tasks with several files on one image (archives) overwrote each other in `download` and scans
- An invalid config file crashed with a traceback instead of an error message
- Files with the same stem (`a.exe`, `a.dll`) or the same name in different folders overwrote each other's results; re-scans of zips with the same name did too
- `re-scan` didn't find the trace in a result folder unpacked with `--unpack`
- `report` and `browser` resolved the key secret (env or command) only to build task links
- A failed unpack reported the task as both done and failed
- Running `unpack` on an already unpacked directory deleted the unpacked logs
- `--amsi` and `--dex` downloaded nothing unless combined with `-A`, `-f`, `-p` or `-a`
- A progress row stayed on screen forever after an unexpected error in a scan
- `download --query --count N` downloaded more than `N` tasks and could loop over the first page
- `email` wrote headers next to the source file instead of the output directory when given a path
- Scanning a folder sent its subdirectories to the sandbox as files
- HTTP errors other than 401 were silently swallowed
- A DLL hook with `no-retval` and no strategy crashed with `IndexError`
- Shortened file names lost the dot before the extension
- `report` started a process pool even for a single report
- The `ssh` config option was documented as `login` instead of `username`

## 0.3.0

### Added

- `completion` command for generating and installing shell completions (bash, zsh, fish)
- `--all` flag for `images` command to fetch images from all configured sandboxes
- `--suspicious` flag for `report` command to include suspicious detects
- `--open-browser` flag for `scan`, `scan-new` and `re-scan` commands
- `--preserve-filename` flag for `scan-new` to keep the original filename during analysis
- `--wait-timeout` option for `scan-new` (useful for heavy samples)
- `--timeout` option for `re-scan` (response waiting time for large traces)
- `--amsi` and `--dex` download options for `scan`, `scan-new` and `download` commands
- `--concurrency` and `--read-timeout` options for `download` command
- `--query` and `--count` options for `download` command to search and download tasks
- `--unimon-hooks`, `--fileextractor-excludes`, `--no-procdumps-on-finish`, `--disable-lightweight-dumps` and `--file-type-as-ext` options for `scan-new`
- `--debug` download option for `re-scan`
- `--sample` option for `download` command to download the original sample submitted for analysis (saved as `<sample_name>.bin`)
- `description` field in sandbox config
- `rules-path` config option for specifying a base path to the rules directory
- Support for task links in `download` command
- Support for wildcard scan files on Windows

### Changed

- **Breaking:** `--procdump-new-processes-on-finish` renamed to `--no-procdumps-on-finish` (inverted semantics)
- **Breaking:** `--latest` flag removed from `report` command
- `email` command description changed from "Send an email" to "Upload an email"
- `--rules` now accepts platform aliases (`windows`, `linux`) in addition to paths
- `--crashdumps` short flag changed from `-c` to `-C` in `download` command
- `report` command now supports download output without `scan_config.json`
- `report --key` is now used only for link generation when `scan_config.json` is missing
- CLI startup optimized via lazy command registration
- Internal architecture refactored: `utils/` → `services/`, `internal/` → `core/`, split `_common.py` into focused modules

### Fixed

- Download race condition where concurrent downloads could overwrite files with the same name
- Various typos in help texts and comments

## 0.2.50

### Fixed

- Don't clean last line in scanner output (was overriding results)
- Resolve mypy type issues

## 0.2.49

### Added

- New parameter to fine-tune the scan (`--disable-lightweight-dumps`)

## 0.2.48

### Added

- New artifact types for download from sandbox (AMSI dumps, DEX dumps)
- Wildcard support for scan files on Windows

## 0.2.47

### Added

- Internal improvements

## 0.2.46

### Added

- Save debug files on rescan
- Remove "safe" suffix from the analysis filename

## 0.2.45

### Added

- Option to pass fileextractor excludes (`--fileextractor-excludes`)

## 0.2.44

### Added

- New scanner options (`--unimon-hooks`, `--no-procdumps-on-finish`, `--file-type-as-ext`)

## 0.2.43

### Added

- Shell completion command (`sandbox-cli completion`)

### Changed

- Refactor file names in unpack output

## 0.2.42

### Added

- Download any unknown artifact types

### Fixed

- Missing sandbox link in `md` report output

## 0.2.41

### Added

- Wait timeout option for scans (`--wait-timeout`)
- Support for task links in download command

## 0.2.40

### Fixed

- Incorrect task parsing in download command

## 0.2.39

### Added

- Option to show suspicious detects in report (`--suspicious`)
- Show elapsed time when scan is done
- Show malware detects always on top

### Fixed

- Handle socket timeout error while downloading files

## 0.2.38

### Added

- Correct handling of the timeout that occurred during scan and re-scan

## 0.2.34

### Added

- Options for downloading all tasks from the sandbox (requires a key with a special permission and support for the new API)

## 0.2.33

### Added

- Option for managing the timeout when creating a task on re-scan

## 0.2.32

### Added

- Add option to specifying outbound connections when scanning

## 0.2.31

### Added

- Add option to specify custom browser in config [#9](https://github.com/Security-Experts-Community/sandbox-cli/pull/9)

## 0.2.30

### Added

- Add new command `browser` to open old reports in browser [#8](https://github.com/Security-Experts-Community/sandbox-cli/pull/8/files)
- Add option to automatically open analysis link in browser [#7](https://github.com/Security-Experts-Community/sandbox-cli/pull/7)

### Fixed

- Default python module `webbrowser` doesn't work correctly by default in some systems (e.g. MacOS) [#9](https://github.com/Security-Experts-Community/sandbox-cli/pull/9)
- Fix rewriting files with the same name when downloading artifacts [#6](https://github.com/Security-Experts-Community/sandbox-cli/pull/6)
- Fix encoding issues when unpacking logs [#5](https://github.com/Security-Experts-Community/sandbox-cli/pull/5)

## 0.2.29

### Fixed

- Fixed bug in path resolving

## 0.2.28

### Added

- Installing the package using `Nix` and documentation [#4](https://github.com/Security-Experts-Community/sandbox-cli/pull/4)

## 0.2.27

### Added

- Specifying the base path to the rules using the config [#2](https://github.com/Security-Experts-Community/sandbox-cli/pull/2)

### Fixed

- Problem with spaces in paths when saving files [#3](https://github.com/Security-Experts-Community/sandbox-cli/pull/3)

## 0.2.26

### Added

- Project documentation in `mkdocs` format
- Project logos

### Changed

- Rename `compiler` option to `rules`
- Refactoring of the internal code base before the public release

## 0.2.25

### Added

Internal development
