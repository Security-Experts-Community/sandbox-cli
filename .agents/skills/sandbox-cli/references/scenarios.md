# Scenarios

Ready-to-run recipes. Every command below works as is; add `-J` when you parse the output
and `-k <key>` when the task needs a sandbox other than the default.

## Contents

- [Analyze samples](#analyze-samples)
  - [One file, default image](#one-file-default-image)
  - [Linux sample](#linux-sample)
  - [Every image of a platform](#every-image-of-a-platform)
  - [Many files or a folder](#many-files-or-a-folder)
  - [DLL, script or document that needs a launcher](#dll-script-or-document-that-needs-a-launcher)
  - [Sample that needs a specific name](#sample-that-needs-a-specific-name)
  - [Sample with dependencies](#sample-with-dependencies)
  - [Archives](#archives)
- [Tune the analysis](#tune-the-analysis)
  - [Slow or evasive malware](#slow-or-evasive-malware)
  - [Network: C2 back-connect, TLS](#network-c2-back-connect-tls)
  - [Bootkits and reboot persistence](#bootkits-and-reboot-persistence)
  - [Manual analysis over VNC](#manual-analysis-over-vnc)
  - [Memory dumps](#memory-dumps)
  - [Dropped files](#dropped-files)
  - [Extra monitoring: syscall, DLL and unimon hooks](#extra-monitoring-syscall-dll-and-unimon-hooks)
  - [Exclude noise from extraction and dumps](#exclude-noise-from-extraction-and-dumps)
  - [Urgent task](#urgent-task)
- [Get results](#get-results)
  - [User pasted a task link](#user-pasted-a-task-link)
  - [Tasks from several sandboxes](#tasks-from-several-sandboxes)
  - [Latest tasks or a search query](#latest-tasks-or-a-search-query)
  - [Something extra from an old task](#something-extra-from-an-old-task)
  - [A sandbox_logs.zip from the web UI](#a-sandbox_logszip-from-the-web-ui)
- [Read results](#read-results)
  - [Verdict](#verdict)
  - [What the sample did](#what-the-sample-did)
  - [Compare images or runs](#compare-images-or-runs)
- [Develop correlation rules](#develop-correlation-rules)
  - [Rules layout](#rules-layout)
  - [Check a rule on an existing trace](#check-a-rule-on-an-existing-trace)
  - [Run rule tests](#run-rule-tests)
  - [Scan with your rules](#scan-with-your-rules)
  - [Compiled rules for another service](#compiled-rules-for-another-service)
- [Other tasks](#other-tasks)

## Analyze samples

### One file, default image

```sh
sandbox-cli scanner scan-new sample.exe -U -J
```

Runs on `win10-22H2-x64` for 300 s, downloads logs and video into `./sandbox/win10-22H2-x64/`
and unpacks them. Expect about `duration + 1-2 min` of wall time per task. Use `-t 60`
for a quick look and `-t 600` and more for samples that wait before acting (10-3599 s).

### Linux sample

```sh
sandbox-cli scanner scan-new payload.elf -i ubuntu-jammy-x64 -U -J
```

ELF files, shell scripts and other Linux samples need a Linux image: the default image
is Windows. Image ids: `ubuntu-jammy-x64`, `redos-8-x64`, `redos-murom-x64`,
`astralinux-smolensk-x64`, `altworkstation-10-x64`.

### Every image of a platform

```sh
sandbox-cli scanner scan-new payload.elf -i linux -U -J
sandbox-cli scanner scan-new sample.exe -i windows -U -J
```

`-i linux` / `-i windows` expand to every image of that platform the sandbox has.
Each image is a separate task in `./sandbox/<image>/`. Use it to find environment-dependent
behavior. `-i` can also be repeated: `-i win10-22H2-x64 -i win11-23H2-x64`. Don't mix
platforms in one run.

### Many files or a folder

```sh
sandbox-cli scanner scan-new samples/ -U -J
sandbox-cli scanner scan-new a.exe b.dll c.js -i win10-22H2-x64 -U -J
```

Folders are scanned recursively. Results go to `./sandbox/<file-stem>/<image>/`; files with
the same stem use the full name (`a.exe/`, `a.dll/`), and same names from different folders
get `_1`, `_2`. Take the folder of each file from `out_dir` in its JSON line.
`max-workers` of the key limits how many tasks run at once; the rest wait in the queue.
Prefer one command with many files over many parallel commands: the limit applies per
command, so parallel commands overload the sandbox queue.

### DLL, script or document that needs a launcher

```sh
sandbox-cli scanner scan-new lib.dll --cmd 'rundll32.exe {file},DllRegisterServer' -U -J
sandbox-cli scanner scan-new lib.dll --cmd 'rundll32.exe {file},#1' -U -J
sandbox-cli scanner scan-new script.ps1 --cmd 'powershell.exe -ExecutionPolicy Bypass -File {file}' -U -J
```

`{file}` becomes the path of the sample inside the VM. Without `--cmd` the sandbox decides
how to start the file from its type.

### Sample that needs a specific name

```sh
sandbox-cli scanner scan-new 3f2a9c...e1 -n invoice.docm -U -J      # set the name inside the VM
sandbox-cli scanner scan-new 3f2a9c...e1 -fte -U -J                 # use the detected file type as the extension
sandbox-cli scanner scan-new sample.exe_ -pf -U -J                  # keep the name as is
```

By default a trailing `_` or `~` is stripped (`sample.exe_` → `sample.exe`), the usual way
to store samples so they don't run by accident. `-n` applies to every file of the command.

### Sample with dependencies

```sh
sandbox-cli scanner scan-new loader.exe -e payload.dll -e config.dat -U -J
```

`-e` uploads extra files next to the sample (DLL side-loading, configs, second stages).

### Archives

```sh
sandbox-cli scanner scan-new samples.zip -ua -U -J
```

Without `-ua` the sandbox runs the archive itself as one file and nothing inside it
executes; the CLI warns about it. `-ua` sends archives (zip, 7z, rar, gzip, bzip2, xz,
cab, tar; not docx/jar/apk) through the full scan: the sandbox unpacks them with the
`passwords` from the config (`infected`, `311138`, `password`, `12345678`, `P@ssw0rd!` by
default) and analyzes every extracted file. Add the password to `passwords` in the config
if the archive uses another one (see [config.md](config.md)).

Each extracted file gets its own folder: `./sandbox/<image>/<file>/`, and you get one
JSON line per archive (its `out_dir` holds the per-file folders). Other files of the
same command still run as usual. `-dc`, `-e`, `-S` and `-V` don't work for archives,
and the CLI rejects them before uploading.

## Tune the analysis

### Slow or evasive malware

```sh
sandbox-cli scanner scan-new sample.exe -t 900 -W 5400 -U -J
```

`-t` is the time the sample runs. `-W` is how long the CLI waits for the result; by
default `4 × duration + 120..300 s`. When the CLI gives up (`got timeout while waiting`)
the task keeps running in the sandbox: fetch it later with `download <link>`.

### Network: C2 back-connect, TLS

```sh
sandbox-cli scanner scan-new rat.exe -oc 203.0.113.10 -oc 203.0.113.11 -U -J   # allow connections to these IPs
sandbox-cli scanner scan-new sample.exe -M -U -J                                # no TLS interception
```

The VM is isolated by default. `-oc` whitelists IP addresses for outbound connections
(for example your own listener). `-M` disables the sandbox certificate injection for
samples that pin certificates and refuse to talk through interception.
Traffic always ends up in `network/tcpdump.pcap`.

### Bootkits and reboot persistence

```sh
sandbox-cli scanner scan-new dropper.exe -b -bd 120 -U -J
```

`-b` adds a bootkitmon analysis stage; `-bd` is its duration (at least 10 s, default 60).

### Manual analysis over VNC

```sh
sandbox-cli scanner scan-new installer.exe -V full -dc -t 900 -ob -J
```

`-V full` lets you control the VM from the web UI (`read-only` only watches); `-dc`
turns off the auto-clicker, which otherwise clicks through dialogs while you work;
`-ob` opens the task in the browser. Pick a long
`-t`: the VM stops when the analysis time ends. `-S` uploads the sample without
starting it, so you start it yourself.

### Memory dumps

```sh
sandbox-cli scanner scan-new packed.exe -p -D -U -J        # process dumps, decompressed
sandbox-cli scanner scan-new packed.exe -p -D -dl -U -J    # full dumps instead of lightweight ones
```

Dumps land in `process_dump/<process name>`; without `-D` they stay zstd-compressed.
By default the sandbox also dumps every process still alive at the end; `-P` turns that off.
`-am` downloads AMSI dumps (script content passed to AMSI), `-dx` DEX dumps (Android).

### Dropped files

```sh
sandbox-cli scanner scan-new dropper.exe -f -U -J    # files the sample created
sandbox-cli scanner scan-new dropper.exe -A -U -J    # files and process dumps
sandbox-cli scanner scan-new dropper.exe -a -U -J    # everything, can be gigabytes
```

Files keep their guest path under `artifacts/`.

### Extra monitoring: syscall, DLL and unimon hooks

```sh
sandbox-cli scanner scan-new sample.exe -s syscalls.txt -U -J
sandbox-cli scanner scan-new sample.exe -dll dll-hooks/ -U -J
sandbox-cli scanner scan-new sample.exe -u unimon-hooks.txt -U -J
```

- `syscalls.txt`: one syscall name per line.
- `dll-hooks/`: one `<dll name>.txt` per DLL (subfolders allowed, `kernel32.txt` hooks
  `kernel32.dll`). Each line is `[System32,|SysWOW64,]Function,[no-retval,]log|log+stack[,PARAM:TYPE...]`,
  `#` starts a comment. The CLI rejects hooks on slow functions (`RtlAllocateHeap`,
  `GetModuleFileNameA/W`) and malformed lines before uploading, with `file:line` in the error.

### Exclude noise from extraction and dumps

```sh
sandbox-cli scanner scan-new sample.exe -fe fileextractor-excludes.txt -pe procdump-excludes.txt -p -f -U -J
```

Both files hold one regular expression per line: `-fe` matches file paths not to extract,
`-pe` matches process paths not to dump.

### Urgent task

```sh
sandbox-cli scanner scan-new sample.exe -pr 4 -U -J
```

Priority 1-4 (default 3): higher numbers start sooner when the sandbox queue is busy.

## Get results

### User pasted a task link

```sh
sandbox-cli download https://sandbox.example.com/tasks/<uuid> -L -U -J
```

The host in the link selects the sandbox, no `-k` needed. A bare `<uuid>` uses `-k`
(default key). Links can come as copied from the browser: with or without `https://`,
with a port, query string or `#fragment`, in any letter case; `/tasks/<uuid>` and
`/<uuid>` paths both work. `download` fetches only what you ask for: `-L` logs (needed for `-U` and
`report`), `-v` video, `-sa` the original sample, plus the usual `-p/-f/-A/-a/-d/-C/-am/-dx`.
Results go to `./downloads/<uuid>/<image>/`.

### Tasks from several sandboxes

```sh
sandbox-cli download \
  https://sb1.example.com/tasks/<uuid1> \
  sb2.example.com/tasks/<uuid2> \
  <uuid3> -k staging \
  -L -U -J
```

Put every link and id into one call. Each link goes to the `[[sandbox]]` whose `host`
matches the link host (case, scheme and port don't matter); bare ids go to `-k`. One
connection per sandbox is shared by its tasks, and `-j` limits all downloads together.
Every task gets its own `<out>/<uuid>/` and its own JSON line.

The CLI checks all links before downloading: an id that isn't a UUID or a host that no
`[[sandbox]]` has stops the command with one error listing all of them
(`Invalid task id: …; Unknown sandbox host: …`). A task the sandbox doesn't know is
reported as `{"status": "skipped", "reason": "no report"}` and the others continue.

### Latest tasks or a search query

```sh
sandbox-cli download -q "" -c 10 -L -J               # the 10 latest tasks of the default key
sandbox-cli download -q "<query>" -c 50 -k staging -L -J
```

`-q` takes the search query of the sandbox web UI; an empty string means "latest".
`-c` caps the number of tasks (default 20).

### Something extra from an old task

```sh
sandbox-cli download <link> -p -D -J     # only process dumps
sandbox-cli download <link> -sa -J       # the original sample (live malware!)
```

Downloading into the same folder again overwrites logs and adds `_1`, `_2` to other files.

### A sandbox_logs.zip from the web UI

```sh
sandbox-cli unpack sandbox_logs.zip
```

Extracts next to the archive (`./sandbox_logs/`) and unpacks the logs there. `unpack <dir>`
does the same for a folder; running it again is safe.

## Read results

### Verdict

```sh
sandbox-cli report ./sandbox -su -J
```

One line per result with `verdict` (malware detections, plus suspicious ones with `-su`),
`static` (AV and static engines), `memory` (detections in process dumps), `network`
(network alerts) and the task link. It needs logs next to each `report.json`, so run
it on folders produced by scans or by `download -L`. For a human-readable table use
`-m md` or plain output.

Inside an unpacked result `correlated/malware.log` holds the malicious detections; no file
means none fired.

### What the sample did

```sh
cd sandbox/win10-22H2-x64
ls normalized/                                   # one <plugin>.log per drakvuf plugin
head -1 normalized/procmon.log | jq .            # inspect the fields before filtering
jq -r '."detect.name" // empty' correlated/events-correlated.log | sort | uniq -c | sort -rn
jq -r 'select(."event.name" == "Auxiliary.ObtainNetworkAlert") | .s_msg' correlated/events-correlated.log
```

Typical plugins: `procmon` (processes), `filetracer` (files), `regmon` (registry),
`socketmon` and `netdump` (network), `inject` (injections), `syscall` (syscalls).
The set depends on the image. Check the fields of a plugin with `head -1 | jq .` instead
of guessing them. Logs can be large: filter with `jq -c 'select(...)'` or `grep`.

### Compare images or runs

```sh
sandbox-cli report ./sandbox -su -J | jq -c '{image, verdict}'
diff <(jq -r '."detect.name" // empty' run1/correlated/events-correlated.log | sort -u) \
     <(jq -r '."detect.name" // empty' run2/correlated/events-correlated.log | sort -u)
```

## Develop correlation rules

### Rules layout

```text
<rules-path>/
├── taxonomy/
├── windows/
│   ├── correlation/<rule folders>
│   └── normalization/...
└── linux/
    └── ...
```

`-r windows` / `-r linux` resolve against `rules-path` from the config; any other value
is a path. The CLI copies `<platform>/../taxonomy` next to the rules before compiling.
Rules compile on the first sandbox of the config over SSH (needs `ssh` credentials there)
or, with `-l`, in a local Docker container (needs the `[docker]` section).

If `-r` points at a file instead of a folder, the CLI treats it as an archive with already
compiled rules: it uploads the file as is and skips compilation (`-l` has nothing to do then).
The file has to be the tar.gz from `rules compile` (or from the rules CI) with
`event_correlation_graph.json` and `event_normalization_graph.json` inside — anything else is
rejected before the upload, because the sandbox would silently fall back to its own rules.
Use it to reuse one archive for many scans when compiling is not an option:

```sh
sandbox-cli rules compile windows -o out/
sandbox-cli scanner scan-new sample.exe -r out/compiled-rules.local.tar.gz -U -J
```

### Check a rule on an existing trace

The fastest loop when you write or fix a rule: no new detonation, about 20 s per run.

```sh
sandbox-cli scanner re-scan sandbox/win10-22H2-x64 -r windows -U -J
jq -r '."detect.name"' sandbox/rescan/correlated/malware.log | sort -u
```

`re-scan` takes a result folder of a previous run (unpacked or not) or a `sandbox_logs.zip`;
it finds `drakvuf-trace.log.zst` and `tcpdump.pcap` itself. Results go to `./sandbox/rescan/`
(`rescan_<N>` for several traces, the zip name for archives). Use `-o` to keep runs apart.

### Run rule tests

```sh
sandbox-cli rules test ~/rules/windows/correlation/my_rule
```

Runs the tests of the rules under the given folder; the path must be inside
`correlation/` or `normalization/`. Fails with exit code 1 when a test fails.

### Scan with your rules

```sh
sandbox-cli scanner scan-new sample.exe -r windows -U -J
```

### Compiled rules for another service

```sh
sandbox-cli rules compile windows -o out/
```

Writes `out/compiled-rules.local.tar.gz`. Feed it back to `scan-new`, `scan` or `re-scan`
with `-r out/compiled-rules.local.tar.gz` to skip compilation.

## Other tasks

| Task | Command |
| --- | --- |
| Which images a sandbox has | `sandbox-cli images -k <key> -J` (`-ak` for all sandboxes) |
| Email headers | `sandbox-cli email *.eml -o headers/ -J` → `headers/<name>.eml.headers` |
| Open a result in the browser | `sandbox-cli browser sandbox/win10-22H2-x64` |
| Shell completion | `sandbox-cli completion zsh -I` (bash, fish) |
| Version | `sandbox-cli --version` |
