!!! info "Info"

    For this option, you need to specify at least one sandbox in the config.

It is often necessary to download some information from the task.

If you don't want to poke all the buttons in the interface, you can simply run one of the following commands:

<!-- termynal -->

```sh
# Download all available data by task id
$ sandbox-cli download --all b2ece7fa-b3db-4ed5-86c7-2bba4b55f563

# Download only sandbox logs and automatically convert
$ sandbox-cli download --logs --unpack b2ece7fa-b3db-4ed5-86c7-2bba4b55f563

# Or you can just provide a link to the task
$ sandbox-cli download --all https://sandbox.example.com/tasks/b2ece7fa-b3db-4ed5-86c7-2bba4b55f563

# You can also download multiple tasks in one request
$ sandbox-cli download --all b2ece7fa-b3db-4ed5-86c7-2bba4b55f563 https://sandbox.example.com/tasks/c7d567f0-5805-4191-a0f1-e35158dc4e80
```

The structure of the 'downloads` directory.

```sh title="tree" hl_lines="2 11"
downloads/
├── b2ece7fa-b3db-4ed5-86c7-2bba4b55f563
│   ├── artifacts/
│   ├── debug/
│   ├── drakvuf-trace.log.zst
│   ├── events-correlated.log.gz
│   ├── events-normalized.log.gz
│   ├── process_dump/
│   ├── tcpdump.pcap
│   └── video.mp4
└── c7d567f0-5805-4191-a0f1-e35158dc4e80
    ├── debug/
    ├── drakvuf-trace.log.zst
    ├── events-correlated.log.gz
    ├── events-normalized.log.gz
    ├── tcpdump.pcap
    └── video.mp4
```

!!! tip "Tip"

    If you provide a full link to the sandbox, you do not need to specify the key name for this sandbox.

    ```sh
    sandbox-cli download --all https://sandbox-1.example.com/tasks/... https://sandbox-2.example.com/tasks/...
    ```

    For example, if the keys are named `sandbox-1` and `sandbox-2`.
    The key `sandbox-1` will be used to download the first task, and `sandbox-2` for the second.

## Help

<!-- termynal -->

```sh
$ sandbox-cli download --help

Usage: sandbox-cli download [ARGS] [OPTIONS]

Download any artifact from the sandbox.

╭─ Arguments ────────────────────────────────────────────────────────────────╮
│ *  TASKS_ID  Links to tasks or task ids [required]                         │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ Download options ─────────────────────────────────────────────────────────╮
│ --all         -a  Download all artifacts [default: False]                  │
│ --debug       -d  Download debug artifacts [default: False]                │
│ --artifacts   -A  Download artifacts [default: False]                      │
│ --files       -f  Download files [default: False]                          │
│ --crashdumps  -c  Download crashdumps (maybe be more 1GB) [default: False] │
│ --procdumps   -p  Download procdumps [default: False]                      │
│ --video       -v  Download video [default: False]                          │
│ --logs        -l  Download logs [default: False]                           │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ Parameters ───────────────────────────────────────────────────────────────╮
│ --out         -o  Output directory [default: downloads]                    │
│ --decompress  -D  Decompress downloaded files [default: False]             │
│ --unpack      -U  Unpack downloaded files [default: False]                 │
╰────────────────────────────────────────────────────────────────────────────╯
╭─ Sandbox ──────────────────────────────────────────────────────────────────╮
│ --key  -k  The key to access the sandbox test-1,test-2 [default: test-1]   |
╰────────────────────────────────────────────────────────────────────────────╯
```
