from pathlib import Path, PurePath

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
        raise RuntimeError("Empty function name")

    func_name = args[0]
    if func_name in slow_dll_methods:
        raise RuntimeError(f'Function "{func_name}" considered slow')

    if len(args) < 2 or not args[1]:
        raise RuntimeError("Empty strategy")

    strategy: str
    function_args: list[str]

    if args[1] == "no-retval":
        strategy = args[2]
        function_args = args[3:]
    else:
        strategy = args[1]
        function_args = args[2:]

    if strategy not in ("log", "log+stack"):
        raise RuntimeError("Bad strategy")

    for arg in function_args:
        if not arg:
            raise RuntimeError(f"Extra comma in function argument list of {func_name}")


def _merge_dll_hooks(
    dll_hooks_file: Path,
    name: PurePath,
    dll_hooks_cache: set[str],
) -> bytes:
    chunks: list[bytes] = []
    with dll_hooks_file.open() as file:
        for hook in file:
            hook = hook.strip()
            if hook == "" or hook.startswith("#"):
                continue

            _validate_hook(hook)
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
        raise RuntimeError("No DLL hooks found")

    return merged_hooks
