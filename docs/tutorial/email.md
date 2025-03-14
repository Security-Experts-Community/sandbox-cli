!!! info "Info"

    For this option, you need to specify at least one sandbox in the config.

To get the email headers, specify the `eml` file in the parameters.

<!-- termynal -->

```sh
$ sandbox-cli email file.eml
```

The files will be downloaded to the `downloads` directory with the `headers` suffix.

```sh title="tree"
downloads/
└── file.eml.headers
```

!!! example "Usage example"

    It is useful when it is necessary to decode or extract the headers of an email without the content itself.

## Help

<!-- termynal -->

```sh
$ sandbox-cli email --help

Usage: sandbox-cli email [ARGS] [OPTIONS]

Send an email and get its headers

╭─ Arguments ─────────────────────────────────────────────────╮
│ *  EMAILS  The path to the email files [required]           │
╰─────────────────────────────────────────────────────────────╯
╭─ Parameters ────────────────────────────────────────────────╮
│ --out  -o  Output directory [default: downloads]            │
╰─────────────────────────────────────────────────────────────╯
╭─ Sandbox ───────────────────────────────────────────────────╮
│ --key  -k  The key to access the sandbox                    │
│            test-1,test-2,test-3 [default: test-1]           │
╰─────────────────────────────────────────────────────────────╯
```
