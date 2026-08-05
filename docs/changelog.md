# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
