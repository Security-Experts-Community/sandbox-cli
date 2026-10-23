---
name: sandbox-cli
description: Drive the `sandbox-cli` tool for PT Sandbox (ptsandbox behavioral malware analysis) to submit files, folders and password-protected archives for analysis, tune the VM run (images, duration, launch command, network, VNC, hooks, dumps), fetch results of existing tasks by link or id, unpack and read drakvuf/correlation logs, summarize verdicts, re-scan traces with new correlation rules, test and compile rules, list VM images. Use this skill whenever the user wants to scan, detonate or analyze a sample in the sandbox, check what a file does, get or re-download task results, read sandbox logs, compare runs, or develop sandbox rules, even if they just say "check this file in the sandbox", paste a sandbox task URL, or mention `scan-new`, `re-scan`, `drakvuf-trace`, `report.json` or `sandbox_logs.zip`.
---

# sandbox-cli

`sandbox-cli` submits samples to PT Sandbox, waits for the behavioral analysis, downloads
the results into predictable folders and converts the logs into greppable JSON lines.
The index below covers the usual tasks; you shouldn't need `--help`.

## Ground rules

1. **Samples are live malware.** Never execute, open or `import` samples, dropped files,
   dumps or the files `-sa` downloads. Read results with `jq`, `grep`, `zcat`. Submitting a
   file uploads it to the sandbox server: submit only what the user asked to analyze.
2. **Parse JSON, not text.** Add `-J` and read stdout: one JSON object per finished task
   (see [JSON output](#json-output)). Messages and progress go to stderr. Every command
   finishes all its tasks and exits with 1 if any of them failed: check `status` of each
   line to see which ones.
3. **Scans are slow.** One task takes about `-t` (default 300 s) plus 1-2 minutes, more
   when the sandbox queue is busy. Run scans in the background or with a timeout of at least
   `4 × t + 300` s. A killed or timed-out CLI doesn't stop the task: fetch it later with
   `download <link>`.
4. **One command, many files.** Pass all files or a folder to one `scan-new`: the key's
   `max-workers` throttles them. Parallel commands overload the sandbox queue.
5. **Keys.** `-k <name>` picks a sandbox from the config; the default is the first one.
   Never print the config or its tokens. Without a config, follow [config.md](references/config.md).
6. **Task links pick their own sandbox.** `download` takes any number of links and ids in
   one call and maps every link to the configured sandbox with the same host, so links
   from different sandboxes mix freely and need no `-k`. Only bare UUIDs use `-k`. Don't
   look up keys or split links into one call per sandbox.

## Scenarios

| The user wants to | Command | Details |
| --- | --- | --- |
| Check a Windows file | `sandbox-cli scanner scan-new sample.exe -U -J` | [one file](references/scenarios.md#one-file-default-image) |
| Check a Linux file (ELF, `.sh`) | `sandbox-cli scanner scan-new payload.elf -i ubuntu-jammy-x64 -U -J` | [linux](references/scenarios.md#linux-sample) |
| Run on every Windows/Linux image | `sandbox-cli scanner scan-new sample.exe -i windows -U -J` | [platforms](references/scenarios.md#every-image-of-a-platform) |
| Check many files or a folder | `sandbox-cli scanner scan-new samples/ -U -J` | [many files](references/scenarios.md#many-files-or-a-folder) |
| Check an archive (with a password) | `sandbox-cli scanner scan-new samples.zip -ua -U -J` | [archives](references/scenarios.md#archives) |
| Run a DLL export or a script | `sandbox-cli scanner scan-new lib.dll --cmd 'rundll32.exe {file},#1' -U -J` | [launcher](references/scenarios.md#dll-script-or-document-that-needs-a-launcher) |
| Give the sample a specific name | `sandbox-cli scanner scan-new <hash> -n invoice.docm -U -J` | [names](references/scenarios.md#sample-that-needs-a-specific-name) |
| Upload dependencies with the sample | `sandbox-cli scanner scan-new loader.exe -e payload.dll -U -J` | [dependencies](references/scenarios.md#sample-with-dependencies) |
| Give a slow sample more time | `sandbox-cli scanner scan-new sample.exe -t 900 -W 5400 -U -J` | [slow malware](references/scenarios.md#slow-or-evasive-malware) |
| Let the sample reach its C2 | `sandbox-cli scanner scan-new rat.exe -oc <ip> -U -J` | [network](references/scenarios.md#network-c2-back-connect-tls) |
| Watch or drive the VM by hand | `sandbox-cli scanner scan-new setup.exe -V full -dc -t 900 -ob -J` | [VNC](references/scenarios.md#manual-analysis-over-vnc) |
| Get memory dumps | `sandbox-cli scanner scan-new packed.exe -p -D -U -J` | [dumps](references/scenarios.md#memory-dumps) |
| Get dropped files | `sandbox-cli scanner scan-new dropper.exe -f -U -J` | [dropped files](references/scenarios.md#dropped-files) |
| Hook extra syscalls or DLL functions | `sandbox-cli scanner scan-new sample.exe -s syscalls.txt -dll hooks/ -U -J` | [hooks](references/scenarios.md#extra-monitoring-syscall-dll-and-unimon-hooks) |
| Get results of a task link | `sandbox-cli download <link> -L -U -J` | [links](references/scenarios.md#user-pasted-a-task-link) |
| Get results of many links (any sandboxes) | `sandbox-cli download <link1> <link2> <uuid> -L -U -J` | [several sandboxes](references/scenarios.md#tasks-from-several-sandboxes) |
| Get the latest tasks / search tasks | `sandbox-cli download -q "" -c 10 -L -J` | [search](references/scenarios.md#latest-tasks-or-a-search-query) |
| Unpack a `sandbox_logs.zip` from the UI | `sandbox-cli unpack sandbox_logs.zip` | [unpack](references/scenarios.md#a-sandbox_logszip-from-the-web-ui) |
| Get the verdict | `sandbox-cli report ./sandbox -su -J` | [verdict](references/scenarios.md#verdict) |
| Find out what the sample did | `jq` over `normalized/<plugin>.log` | [behavior](references/scenarios.md#what-the-sample-did) |
| Check a new rule without a new run | `sandbox-cli scanner re-scan <result-dir> -r windows -U -J` | [re-scan](references/scenarios.md#check-a-rule-on-an-existing-trace) |
| Run rule tests | `sandbox-cli rules test <rules>/windows/correlation/<rule>` | [tests](references/scenarios.md#run-rule-tests) |
| See which images a sandbox has | `sandbox-cli images -k <key> -J` | [other](references/scenarios.md#other-tasks) |

Every scenario, the meaning of each flag and less common tasks (bootkits, TLS, urgent
priority, exclusions, email headers, completion) are in [scenarios.md](references/scenarios.md).

## JSON output

`scanner scan-new`, `scanner scan` and `scanner re-scan` print one line per task:

```json
{"status": "done", "name": "hello.sh", "image": "ubuntu-jammy-x64", "task_id": "2c2e…", "link": "https://sandbox.example.com/tasks/2c2e…", "out_dir": "/abs/sandbox/ubuntu-jammy-x64", "elapsed": 109.1}
{"status": "failed", "name": "a.exe", "image": "win10-22H2-x64", "task_id": null, "link": null, "out_dir": "/abs/sandbox/win10-22H2-x64", "elapsed": 3.2, "reason": "connection error • …"}
```

| Command | Fields |
| --- | --- |
| `download` | `status` (`done`, `failed`, `skipped`), `task_id`, `link`, `out_dir`, `reason` |
| `report` | `sample`, `image`, `sandbox` (link), `verdict`, `static`, `memory`, `network` (lists) |
| `images` | `key`, `image_id`, `name`, `version`, `product_version`, `locale` |
| `email` | `status`, `email`, `headers` (file), `reason` |

`out_dir` is absolute: read the results from there. `task_id` and `link` are `null` when
the upload failed.

When the whole command fails (bad arguments, missing files, invalid config, unknown key)
stdout gets a single `{"status": "error", "reason": "…"}` line and the exit code is 1. When
some tasks failed, the same kind of line (`"Failed 1 of 3 tasks"`) comes last, after the task lines. The CLI
checks files, hooks, IP addresses, rules folders and task ids before uploading anything, so
these errors come back within a second.

## Results

A finished scan folder holds `report.json`, `scan_config.json`, logs and video; with `-U`
also `correlated/`, `normalized/`, `network/`, `drakvuf-trace/` and `raw/`. Start with
`correlated/malware.log` (missing means no malicious detections), then
`normalized/<plugin>.log`. Folder names, file names and log fields:
[output-layout.md](references/output-layout.md).

## Troubleshooting

| Message | What to do |
| --- | --- |
| `To access other commands, specify at least one sandbox in the config` | No config: see [config.md](references/config.md) |
| `invalid config at …` | Fix the TOML or the field named in the message |
| `The specified token is not valid` | The `key` of that sandbox is wrong or expired |
| `Key "x" doesn't exist in config. Available keys: …` | Use one of the listed names |
| `Secret command … failed` / `Environment variable … is not set` | The secret reference of the key can't be resolved |
| `Sandbox doesn't support <image>` | Pick an id from `sandbox-cli images -k <key>` |
| `<file> is an archive: it runs as one file` | Add `-ua` to unpack it |
| `<archive>: … don't work with --unpack-archives` | Drop `-dc`, `-e`, `-S`, `-V` or scan the archive separately |
| `Paths don't exist: …` / `Nothing to scan` | Check the paths; empty folders have nothing to scan |
| `Unknown sandbox host: <host>` | No `[[sandbox]]` in the config has that `host`: add it, or pass the bare UUID with `-k` |
| `got timeout while waiting` | The task still runs: `download <link>` later, or raise `-W` |
| `full report not available` / `scan failed` | The sandbox couldn't finish the task: open the link, try another image |
| `Can't verify ssh-key` | The user runs `ssh <user>@<first sandbox host>` once and accepts the key |
| `ExceptionName: …` | Re-run with `DEBUG=1` for the traceback |

## References

- [scenarios.md](references/scenarios.md): every task with ready commands and flag explanations
- [config.md](references/config.md): config file, secrets, environment variables
- [output-layout.md](references/output-layout.md): result folders, unpacked layout, log fields
- [commands.md](references/commands.md): raw `--help` of every command, for flags not covered above
