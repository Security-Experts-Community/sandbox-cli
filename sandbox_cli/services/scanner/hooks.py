from pathlib import Path, PurePath

from sandbox_cli.core.exceptions import ScanError

slow_dll_methods = frozenset(
    {
        "RtlAllocateHeap",
        "GetModuleFileNameA",
        "GetModuleFileNameW",
    }
)


def _validate_hook(hook: str) -> None:
    args = hook.split(",")

    if args[0] in ("System32", "SysWOW64"):
        args = args[1:]

    if len(args) < 1 or not args[0]:
        raise ScanError("Empty function name")

    func_name = args[0]
    if func_name in slow_dll_methods:
        raise ScanError(f'Function "{func_name}" considered slow')

    if len(args) < 2 or not args[1]:
        raise ScanError("Empty strategy")

    strategy: str
    function_args: list[str]

    if args[1] == "no-retval":
        if len(args) < 3 or not args[2]:
            raise ScanError("Empty strategy")
        strategy = args[2]
        function_args = args[3:]
    else:
        strategy = args[1]
        function_args = args[2:]

    if strategy not in ("log", "log+stack"):
        raise ScanError("Bad strategy")

    for arg in function_args:
        if not arg:
            raise ScanError(f"Extra comma in function argument list of {func_name}")


def _merge_dll_hooks(
    dll_hooks_file: Path,
    name: PurePath,
    dll_hooks_cache: set[str],
) -> bytes:
    try:
        lines = dll_hooks_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise ScanError(f"Can't read {dll_hooks_file}: {e}") from None

    chunks: list[bytes] = []
    for lineno, line in enumerate(lines, start=1):
        hook = line.strip()
        if hook == "" or hook.startswith("#"):
            continue

        try:
            _validate_hook(hook)
        except ScanError as e:
            raise ScanError(f"{dll_hooks_file}:{lineno}: {e}") from None
        prefix = ""
        if hook.startswith("SysWOW64"):
            prefix = "SysWOW64\\"
        elif hook.startswith("System32"):
            prefix = "System32\\"

        hook = f"{prefix}{name},{hook}"

        if hook in dll_hooks_cache:
            continue

        chunks.append(f"{hook}\n".encode())
        dll_hooks_cache.add(hook)
    return b"".join(chunks)


def merge_dll_hooks(dll_hooks_dir: Path) -> bytes:
    dll_hooks_cache: set[str] = set()

    chunks: list[bytes] = []
    for hooks_file in dll_hooks_dir.rglob("*.txt"):
        name = PurePath(hooks_file.relative_to(dll_hooks_dir)).with_suffix(".dll")
        chunks.append(_merge_dll_hooks(hooks_file, name, dll_hooks_cache))

    merged_hooks = b"".join(chunks)
    if not merged_hooks:
        raise ScanError(f"No DLL hooks found in {dll_hooks_dir}")

    return merged_hooks
