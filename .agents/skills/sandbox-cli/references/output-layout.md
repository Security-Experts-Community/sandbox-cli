# Output layout

## Contents

- [Where results go](#where-results-go)
- [Inside a result directory](#inside-a-result-directory)
- [After unpacking](#after-unpacking)
- [Log formats](#log-formats)

## Where results go

`scanner scan-new` / `scanner scan` (default `--out ./sandbox`):

| Input | Directory per task |
| --- | --- |
| one file, one or more images | `<out>/<image-id>/` |
| several files (or a folder) | `<out>/<file-stem>/<image-id>/` |

`scanner re-scan` (default `--out ./sandbox`): `<out>/<zip-stem>/` for a zip, otherwise
`<out>/rescan/` (one trace) or `<out>/rescan_<N>/`.

`download` (default `--out ./downloads`): `<out>/<task-uuid>/<image-id>/`.

When one task has several runs on the same image (files extracted from an archive with
`scan-new -ua`, or old full-scan tasks), each run gets `<image>/<file name>/` with its own
`report.json` and logs; `<image>/` then only groups them.

## Inside a result directory

| Path | When |
| --- | --- |
| `report.json` | always — full task response (`SandboxBaseTaskResponse`) |
| `scan_config.json` | scans — key name and sandbox options, used by `browser` and `report` |
| `events-correlated.log.gz` | logs |
| `events-normalized.log.gz` | logs |
| `drakvuf-trace.log.zst` | logs (raw drakvuf trace, older sandboxes use `.gz`) |
| `tcpdump.pcap` | logs |
| screenshots / video files | scans always, `download -v` |
| `artifacts/<guest path>` | `-f` / `-A` — files dropped during analysis |
| `process_dump/<process name>` | `-p` / `-A` — zstd-compressed unless `-D` |
| `crashdumps/` | `-C` |
| `debug/` | `-d` |
| `amsi/<sha256>.bin`, `dex/<sha256>.bin` | `-am`, `-dx` |
| `other/<sha256>` | `-a`, artifact types unknown to the client |
| `<sample name>.bin` | `download -sa` — the original sample (live malware) |

Name clashes get a `_1`, `_2`, … suffix instead of overwriting.

## After unpacking

`sandbox-cli unpack <dir>` (or `-U`) rewrites the directory in place:

```text
drakvuf-trace/drakvuf-trace.log      decompressed raw trace
correlated/events-correlated.log     all correlation events
correlated/malware.log               events with detect.type == malware
correlated/<detect>.suspicious.log   one file per suspicious detection
correlated/<detect>.silent.log       one file per silent detection
normalized/events-normalized.log     all normalized events
normalized/<plugin>.log              normalized events split by drakvuf plugin
network/tcpdump.pcap
raw/                                 original compressed files
```

A `sandbox_logs.zip` is first extracted into a sibling folder named after the zip.

## Log formats

All `*.log` files are JSON lines (one object per line).

Correlated events carry `detect.type` (`malware` / `suspicious` / `silent`) and
`detect.name`; network alerts have `event.name == "Auxiliary.ObtainNetworkAlert"` with
the message in `s_msg`. Normalized events have a `plugin` field naming the drakvuf plugin
that produced them.

```sh
# detection names with counts
jq -r '."detect.name" // empty' correlated/events-correlated.log | sort | uniq -c | sort -rn
# network alerts
jq -r 'select(."event.name" == "Auxiliary.ObtainNetworkAlert") | .s_msg' correlated/events-correlated.log
# which plugins produced events
ls normalized/
```
