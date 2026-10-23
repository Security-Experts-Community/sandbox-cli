# Command reference

Generated from `sandbox-cli <command> --help` (key list shows a placeholder `main`; run `--help` locally for the real names).

## Contents

- [`scanner scan-new`](#scanner-scan-new)
- [`scanner re-scan`](#scanner-re-scan)
- [`download`](#download)
- [`unpack`](#unpack)
- [`report`](#report)
- [`images`](#images)
- [`browser`](#browser)
- [`email`](#email)
- [`rules compile`](#rules-compile)
- [`rules test`](#rules-test)
- [`scanner scan`](#scanner-scan)
- [`completion`](#completion)

## scanner scan-new

```text
Usage: sandbox-cli scanner scan-new [OPTIONS] FILES

Send files to scan with the sandbox (advanced scan).

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  FILES  Path to the files or folders to scan [required]                                                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --rules -r               The path to the folder with the rules or a platform alias (windows, linux) resolved against │
│                          rules-path                                                                                  │
│ --out -o                 The path where to save the results [default: sandbox]                                       │
│ --local -l               Compile the rules locally using Docker (unix only) [default: False]                         │
│ --upload-timeout -T      Upload timeout in seconds (increase if upload big files) [default: 300]                     │
│ --wait-timeout -W        How long to wait for the task result in seconds (increase for heavy samples or large        │
│                          traces)                                                                                     │
│ --unpack -U              Unpack downloaded logs (see the unpack command) [default: False]                            │
│ --open-browser -ob       Open analysis link in the default browser [default: False]                                  │
│ --json -J                Print results as JSON lines to stdout; messages and progress go to stderr [default: False]  │
│ --preserve-filename -pf  Do not change filename for analysis.                                                        │
│                          When set to false (default behaviour): local/path/to/malware.exe[_~] ->                     │
│                          sandbox/guest/os/malware.exe                                                                │
│                          When set to true name will remain unchanged. [default: False]                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Download Options ───────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --all -a         Download all artifacts [default: False]                                                             │
│ --debug -d       Download debug artifacts [default: False]                                                           │
│ --artifacts -A   Download artifacts (files and procdumps) [default: False]                                           │
│ --files -f       Download files [default: False]                                                                     │
│ --crashdumps -C  Download crashdumps (may be more than 1GB) [default: False]                                         │
│ --procdumps -p   Download procdumps [default: False]                                                                 │
│ --amsi -am       Download amsi-dumps [default: False]                                                                │
│ --dex -dx        Download dex-dumps [default: False]                                                                 │
│ --decompress -D  Decompress downloaded procdumps [default: False]                                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --image -i                       The name of the image to scan (don't mix different platforms) Available images:     │
│                                  altworkstation-10-x64, astralinux-smolensk-x64, redos-8-x64, redos-murom-x64,       │
│                                  ubuntu-jammy-x64, win10-1803-x64, win10-22H2-x64, win11-23H2-x64, win7-sp1-x64,     │
│                                  win7-sp1-x64-ics, win8.1-update1-x64, winserv2016-1198-x64, winserv2019-1879-x64    │
│ --key -k                         The key to access the sandbox main [default: main]                                  │
│ --name -n                        Fake name for the sandbox (if specified more than one file will be applied to all   │
│                                  files)                                                                              │
│ --timeout -t                     Analysis duration in seconds [default: 300]                                         │
│ --syscall-hooks -s               Path to file with syscall hooks (file with syscall names split by newline)          │
│ --dll-hooks-dir -dll             Path to directory with dll hooks                                                    │
│ --unimon-hooks -u                Path to file with unimon hooks                                                      │
│ --fileextractor-excludes -fe     Path to file with fileextractor excludes                                            │
│ --procdump-excludes -pe          Path to file with procdump excludes (regular expressions of process paths, one per  │
│                                  line)                                                                               │
│ --cmd                            Command line for file execution rundll32.exe {file},#1                              │
│ --priority -pr                   Priority of the scan (1-4) [default: 3]                                             │
│ --no-procdumps-on-finish -P      Disable dumps for all created and not finished processes [default: False]           │
│ --disable-lightweight-dumps -dl  Disable lightweight memory dumps (mostly for testing purposes) [default: False]     │
│ --bootkitmon -b                  Enable bootkitmon [default: False]                                                  │
│ --bootkitmon-duration -bd        Bootkitmon duration in seconds [default: 60]                                        │
│ --mitm-disabled -M               Disable MITM [default: False]                                                       │
│ --disable-clicker -dc            Disable clicker [default: False]                                                    │
│ --skip-sample-run -S             Skip sample run [default: False]                                                    │
│ --vnc-mode -V                    VNC mode [choices: disabled, full, read-only] [default: disabled]                   │
│ --extra-files -e                 Extra files to upload                                                               │
│ --outbound-connections -oc       Whitelist of IP addresses to which connections from a VM are allowed (backconnect)  │
│ --file-type-as-ext -fte          Use a file type as an extension for a file                                          │
│ --unpack-archives -ua            Unpack archives in the sandbox with the passwords from the config and analyze every │
│                                  extracted file [default: False]                                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## scanner re-scan

```text
Usage: sandbox-cli scanner re-scan [OPTIONS] TRACES

Send traces to re-scan.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  TRACES  Path to folder with drakvuf-trace.log.zst and tcpdump.pcap or sandbox_logs.zip [required]                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --rules -r          The path to the folder with the rules or a platform alias (windows, linux) resolved against      │
│                     rules-path                                                                                       │
│ --out -o            The path where to save the results [default: sandbox]                                            │
│ --local -l          Compile the rules locally using Docker (unix only) [default: False]                              │
│ --unpack -U         Unpack downloaded logs (see the unpack command) [default: False]                                 │
│ --wait-timeout -W   How long to wait for the task result in seconds (increase for heavy samples or large traces)     │
│ --open-browser -ob  Open analysis link in the default browser [default: False]                                       │
│ --json -J           Print results as JSON lines to stdout; messages and progress go to stderr [default: False]       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Download Options ───────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --all -a         Download all artifacts [default: False]                                                             │
│ --debug -d       Download debug artifacts [default: False]                                                           │
│ --artifacts -A   Download artifacts (files and procdumps) [default: False]                                           │
│ --files -f       Download files [default: False]                                                                     │
│ --crashdumps -C  Download crashdumps (may be more than 1GB) [default: False]                                         │
│ --procdumps -p   Download procdumps [default: False]                                                                 │
│ --amsi -am       Download amsi-dumps [default: False]                                                                │
│ --dex -dx        Download dex-dumps [default: False]                                                                 │
│ --decompress -D  Decompress downloaded procdumps [default: False]                                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key -k  The key to access the sandbox main [default: main]                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## download

```text
Usage: sandbox-cli download [OPTIONS] [ARGS]

Download any artifact from the sandbox.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ TASKS_ID  Links to tasks or task ids                                                                                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --out -o     The path where to save the results [default: downloads]                                                 │
│ --unpack -U  Unpack downloaded logs (see the unpack command) [default: False]                                        │
│ --json -J    Print results as JSON lines to stdout; messages and progress go to stderr [default: False]              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Download Options ───────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --all -a         Download all artifacts [default: False]                                                             │
│ --debug -d       Download debug artifacts [default: False]                                                           │
│ --artifacts -A   Download artifacts (files and procdumps) [default: False]                                           │
│ --files -f       Download files [default: False]                                                                     │
│ --crashdumps -C  Download crashdumps (may be more than 1GB) [default: False]                                         │
│ --procdumps -p   Download procdumps [default: False]                                                                 │
│ --amsi -am       Download amsi-dumps [default: False]                                                                │
│ --dex -dx        Download dex-dumps [default: False]                                                                 │
│ --decompress -D  Decompress downloaded procdumps [default: False]                                                    │
│ --video -v       Download video [default: False]                                                                     │
│ --logs -L        Download logs [default: False]                                                                      │
│ --sample -sa     Download the original sample submitted for analysis [default: False]                                │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Performance ────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --concurrency -j  Maximum number of concurrent downloads [default: 16]                                               │
│ --read-timeout    Read timeout in seconds for each download [default: 300]                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key -k  The key to access the sandbox main [default: main]                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Search ─────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --query -q  Query for searching tasks (leave empty for last tasks)                                                   │
│ --count -c  How many tasks find and download [default: 20]                                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## unpack

```text
Usage: sandbox-cli unpack TRACES

Convert sandbox logs into an analysis-friendly format.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  TRACES  The path to the folder with the raw traces or with the sandbox-logs.zip [required]                        │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## report

```text
Usage: sandbox-cli report [OPTIONS] SRC

Generate short report from sandbox scans.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  SRC  Folder(s) with sandbox reports (recursive search will be used) [required]                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --mode -m         Report output format [choices: cli, md] [default: cli]                                             │
│ --suspicious -su  Include suspicious detects [default: False]                                                        │
│ --json -J         Print results as JSON lines to stdout; messages and progress go to stderr [default: False]         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key -k  The key to access the sandbox main                                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## images

```text
Usage: sandbox-cli images [OPTIONS]

Get available images in the sandbox.

╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --all-keys -ak  Fetch images from all configured sandboxes [default: False]                                          │
│ --json -J       Print results as JSON lines to stdout; messages and progress go to stderr [default: False]           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key -k  The key to access the sandbox main [default: main]                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## browser

```text
Usage: sandbox-cli browser [ARGS]

Open sandbox link in the default browser.

╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ PATH --path  Folder with sandbox report (report.json and scan_config.json) [default: .]                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## email

```text
Usage: sandbox-cli email [OPTIONS] EMAILS

Upload an email and get its headers.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  EMAILS  The path to the email files [required]                                                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --out -o   The path where to save the results [default: downloads]                                                   │
│ --json -J  Print results as JSON lines to stdout; messages and progress go to stderr [default: False]                │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key -k  The key to access the sandbox main [default: main]                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## rules compile

```text
Usage: sandbox-cli rules compile [OPTIONS] RULES

Compile rules into an archive for third-party services.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  RULES --rules -r  The path to the folder with the rules or a platform alias (windows, linux) resolved against     │
│                      rules-path [required]                                                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --out -o    The path where to save the results [default: compiled-rules.local.tmp]                                   │
│ --local -l  Compile the rules locally using Docker (unix only) [default: False]                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## rules test

```text
Usage: sandbox-cli rules test [OPTIONS] RULES_DIR

Run the tests of the rules.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  RULES_DIR  A rule or a folder with rules inside correlation/ or normalization/ [required]                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --local -l  Compile the rules locally using Docker (unix only) [default: False]                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## scanner scan

```text
Usage: sandbox-cli scanner scan [OPTIONS] FILES

Send files to scan with the sandbox.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  FILES  Path to the files or folders to scan [required]                                                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --rules -r           The path to the folder with the rules or a platform alias (windows, linux) resolved against     │
│                      rules-path                                                                                      │
│ --out -o             The path where to save the results [default: sandbox]                                           │
│ --local -l           Compile the rules locally using Docker (unix only) [default: False]                             │
│ --unpack -U          Unpack downloaded logs (see the unpack command) [default: False]                                │
│ --upload-timeout -T  Upload timeout in seconds (increase if upload big files) [default: 300]                         │
│ --open-browser -ob   Open analysis link in the default browser [default: False]                                      │
│ --json -J            Print results as JSON lines to stdout; messages and progress go to stderr [default: False]      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Download Options ───────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --all -a         Download all artifacts [default: False]                                                             │
│ --debug -d       Download debug artifacts [default: False]                                                           │
│ --artifacts -A   Download artifacts (files and procdumps) [default: False]                                           │
│ --files -f       Download files [default: False]                                                                     │
│ --crashdumps -C  Download crashdumps (may be more than 1GB) [default: False]                                         │
│ --procdumps -p   Download procdumps [default: False]                                                                 │
│ --amsi -am       Download amsi-dumps [default: False]                                                                │
│ --dex -dx        Download dex-dumps [default: False]                                                                 │
│ --decompress -D  Decompress downloaded procdumps [default: False]                                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox Options ────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --image -i            The name of the image to scan (don't mix different platforms) Available images:                │
│                       altworkstation-10-x64, astralinux-smolensk-x64, redos-8-x64, redos-murom-x64,                  │
│                       ubuntu-jammy-x64, win10-1803-x64, win10-22H2-x64, win11-23H2-x64, win7-sp1-x64,                │
│                       win7-sp1-x64-ics, win8.1-update1-x64, winserv2016-1198-x64, winserv2019-1879-x64               │
│ --key -k              The key to access the sandbox main [default: main]                                             │
│ --name -n             Fake name for the sandbox (if specified more than one file will be applied to all files)       │
│ --timeout -t          Analysis duration in seconds [default: 300]                                                    │
│ --syscall-hooks -s    Path to file with syscall hooks (file with syscall names split by newline)                     │
│ --dll-hooks-dir -dll  Path to directory with dll hooks                                                               │
│ --cmd                 Command line for file execution rundll32.exe {file},#1                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## completion

```text
Usage: sandbox-cli completion [OPTIONS] SHELL

Generate or install shell completion.

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  SHELL  Shell to generate completion for [choices: bash, zsh, fish] [required]                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --install -I  Install the completion script to the default location for the current shell and add it to the RC file  │
│               [default: False]                                                                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

