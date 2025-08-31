from pathlib import Path
from typing import Annotated

from cyclopts import App, Parameter, validators

from sandbox_cli.console import console
from sandbox_cli.utils.compiler import compile_rules_internal, test_rules_internal

rules = App(
    name="rules",
    help="Working with raw sandbox rules.",
    help_format="markdown",
)


@rules.command(name="compile")
async def compile_rules(
    rules: Annotated[
        Path,
        Parameter(
            name=["--rules", "-r"],
            help="The path to the folder with the rules",
            validator=validators.Path(exists=True),
        ),
    ],
    /,
    out: Annotated[
        Path,
        Parameter(
            name=["--out", "-o"],
            help="The path where to save the compiled rules",
            required=False,
        ),
    ] = Path("compiled-rules.local.tmp"),
    is_local: Annotated[
        bool,
        Parameter(
            name=["--local", "-l"],
            negative="",
            help="The rules will be compiled locally using Docker (unix only)",
        ),
    ] = False,
) -> None:
    """
    Get compiled rules for working with third-party services.
    """

    out.mkdir(exist_ok=True, parents=True)
    out = out.expanduser().resolve()

    with console.status(f"{console.INFO} Waiting for the rules to be compiled"):
        data = await compile_rules_internal(rules_dir=rules, is_local=is_local, compiled_rules_dir=out)
        (out / "compiled-rules.local.tar.gz").write_bytes(data)

    console.info(f"Rules saved to {out / 'compiled-rules.local.tar.gz'}")


@rules.command(name="test")
async def test_rules(
    rules: Annotated[
        Path,
        Parameter(
            name=["--rules", "-r"],
            help="The path to the folder with the rules",
            validator=validators.Path(exists=True),
        ),
    ],
    /,
    is_local: Annotated[
        bool,
        Parameter(
            name=["--local", "-l"],
            negative="",
            help="The rules will be compiled locally using Docker (unix only)",
        ),
    ] = False,
) -> None:
    """
    Testing written rules.
    """

    with console.status(f"{console.INFO} Testing rules"):
        await test_rules_internal(rules=rules, is_local=is_local)
