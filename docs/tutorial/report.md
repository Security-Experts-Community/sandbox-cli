# View report

After scanning, you need to quickly understand what the sandbox was able to detect and what was not.

To do this, you can generate a short report in the terminal by transferring the directory where the scan data was saved.

<!-- termynal -->

```sh
$ sandbox-cli report sandbox/
```

By default, the report will be printed to the terminal as a table.

??? example "A glance at the generated output in `md` format"

    | Sample | Image | Verdict | Static | Memory | Network |
    | --- | --- | --- | --- | --- | --- |
    |malware.elf|ubuntu-jammy-x64|Trojan-Downloader.Linux.Generic.n|ptesc: crime_linux_ZZ_Diicot__Backdoor__NetworkScanner<br>ptesc: crime_linux_ZZ_Diicot__Backdoor__Updater<br>ptesc: tool_linux_ZZ_UPX__RiskTool<br>ptesc: tool_linux_ZZ_UPX__Trojan__PatchedUPX||ET HUNTING curl User-Agent to Dotted Quad<br>SUSPICIOUS [PTsecurity] GET request in TCP<br>WORM [PTsecurity] Trojan.Worm error message (APT Diicot)|

!!! tip "Tip"

    You can specify multiple folders with reports, they will be combined into one and displayed on the screen.

    ```sh
    sandbox-cli report sandbox-1/ sandbox-2/
    ```

## Help

<!-- termynal -->

```sh
$ sandbox-cli report --help

Usage: sandbox-cli report [ARGS] [OPTIONS]

Generate short report from sandbox scans.

╭─ Arguments ───────────────────────────────────────────────────────────────────────╮
│ *  SRC  Folder(s) with sandbox reports (recursive search will be used) [required] │
╰───────────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ──────────────────────────────────────────────────────────────────────╮
│ --mode    -m  Report output format [choices: cli, md] [default: cli]              │
│ --latest  -l  Reports created in the last 2 hours [default: False]                │
╰───────────────────────────────────────────────────────────────────────────────────╯
```
