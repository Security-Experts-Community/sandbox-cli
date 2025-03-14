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

| Option         | Description                         | Default |
| -------------- | ----------------------------------- | ------- |
| `--debug / -d` | All debug files will be downloaded. | `False` |

### Parameters

| Option          | Description                                                                                           | Default     |
| --------------- | ----------------------------------------------------------------------------------------------------- | ----------- |
| `--rules / -r`  | The path to your own rules.                                                                           | `None`      |
| `--out / -o`    | The path where the analysis results will be saved.                                                    | `./sandbox` |
| `--local / -l`  | Compile rules locally or on the server. <br> I guess you can just ignore this option.                 | `False`     |
| `--unpack / -U` | The downloaded logs will be automatically converted. <br> Learn more in [Analyzing logs](../logs.md). | `False`     |

### Sandbox Options

| Option       | Description                                           | Default |
| ------------ | ----------------------------------------------------- | ------- |
| `--key / -k` | The name of the key for accessing a specific sandbox. | `None`  |

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

Usage: sandbox-cli scanner re-scan [ARGS] [OPTIONS]

Send traces to re-scan.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────╮
│ *  TRACES  Path to folder with drakvuf-trace.log.zst and tcpdump.pcap or sandbox_logs.zip [required] │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Download options ───────────────────────────────────────────────────────────────────────────────────╮
│ --debug  -d  Download debug artifacts [default: False]                                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────╮
│ --rules   -r  The path to the folder with the rules or the default rules from the sandbox            │
│ --out     -o  The path where to save the results [default: sandbox]                                  │
│ --local   -l  The rules will be compiled locally using Docker (unix only) [default: False]           │
│ --unpack  -U  Unpack downloaded files [default: False]                                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────╮
│ --key  -k  The key to access the sandbox test-1,test-2,test-3 [default: test-1]                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
