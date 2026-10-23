!!! info "Info"

    For this option, you need to specify at least one sandbox in the config.

## Quick start

<!-- termynal -->

```sh
$ sandbox-cli scanner re-scan sandbox_logs.zip

[INFO] Using key: name=test-1 max_workers=8
[DONE] sandbox_logs.zip • https://sandbox.example.com/tasks/56ae494b-fffc-11ef-a24b-72ab1bd29c47
```

## Options

### Download options

The same download options as in [scan-new](scan-new.md#download-options) (`-a`, `-d`, `-A`, `-f`, `-C`, `-p`, `-am`, `-dx`, `-D`). Logs are always downloaded.

### Parameters

| Option                  | Description                                                                                           | Default     |
| ----------------------- | ----------------------------------------------------------------------------------------------------- | ----------- |
| `--rules / -r`          | The path to the folder with the rules or the default rules from the sandbox or platform alias.        | `None`      |
| `--out / -o`            | The path where the analysis results will be saved.                                                    | `./sandbox` |
| `--local / -l`          | Compile rules locally using Docker (unix only).                                                       | `False`     |
| `--unpack / -U`         | The downloaded logs will be automatically converted. <br> Learn more in [Analyzing logs](../logs.md). | `False`     |
| `--open-browser / -ob`  | Open the analysis link in the default browser.                                                        | `False`     |
| `--wait-timeout / -W`   | How long to wait for the task result in seconds (increase for large traces).                          | `300`       |

### Sandbox Options

| Option       | Description                                           | Default |
| ------------ | ----------------------------------------------------- | ------- |
| `--key / -k` | The name of the key for accessing a specific sandbox. | first sandbox in the config |

## Cookbook

### Rescan multiple files

<!-- termynal -->

```sh
$ sandbox-cli scanner re-scan sandbox_logs.zip sandbox_logs_1.zip sandbox_logs_2.zip
```

### Rescan with automatic unpacking

<!-- termynal -->

```sh
$ sandbox-cli scanner re-scan -U sandbox_logs.zip sandbox_logs_1.zip sandbox_logs_2.zip
```

### Rescan and view results

<!-- termynal -->

```sh
$ sandbox-cli scanner re-scan -U sandbox_logs.zip sandbox_logs_1.zip sandbox_logs_2.zip

$ sandbox-cli report sandbox/
```

## Help

<!-- termynal -->

```sh
$ sandbox-cli scanner re-scan --help

Usage: sandbox-cli scanner re-scan [OPTIONS] TRACES

Send traces to re-scan.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *  TRACES  Path to folder with drakvuf-trace.log.zst and tcpdump.pcap or     │
│            sandbox_logs.zip [required]                                       │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────╮
│ --rules -r          The path to the folder with the rules or a platform      │
│                     alias (windows, linux) resolved against rules-path       │
│ --out -o            The path where to save the results [default: sandbox]    │
│ --local -l          Compile the rules locally using Docker (unix only)       │
│                     [default: False]                                         │
│ --unpack -U         Unpack downloaded logs (see the unpack command)          │
│                     [default: False]                                         │
│ --wait-timeout -W   How long to wait for the task result in seconds          │
│                     (increase for heavy samples or large traces)             │
│ --open-browser -ob  Open analysis link in the default browser [default:      │
│                     False]                                                   │
│ --json -J           Print results as JSON lines to stdout; messages and      │
│                     progress go to stderr [default: False]                   │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Download Options ───────────────────────────────────────────────────────────╮
│ --all -a         Download all artifacts [default: False]                     │
│ --debug -d       Download debug artifacts [default: False]                   │
│ --artifacts -A   Download artifacts (files and procdumps) [default: False]   │
│ --files -f       Download files [default: False]                             │
│ --crashdumps -C  Download crashdumps (may be more than 1GB) [default: False] │
│ --procdumps -p   Download procdumps [default: False]                         │
│ --amsi -am       Download amsi-dumps [default: False]                        │
│ --dex -dx        Download dex-dumps [default: False]                         │
│ --decompress -D  Decompress downloaded procdumps [default: False]            │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────╮
│ --key -k  The key to access the sandbox main [default: main]                 │
╰──────────────────────────────────────────────────────────────────────────────╯
```
