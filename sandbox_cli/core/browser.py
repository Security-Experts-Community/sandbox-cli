from __future__ import annotations

import webbrowser

from sandbox_cli.console import console
from sandbox_cli.core.config import settings

__all__ = ["open_link"]


def open_link(link: str) -> None:
    if settings.browser is not None:
        webbrowser.register(
            "new_default_browser",
            None,
            webbrowser.GenericBrowser([str(settings.browser.path), *settings.browser.args]),
            preferred=True,
        )
        if not webbrowser.open(link):
            console.error("Can't open link in the specified browser. Please check browser path and args.")
        return

    if not webbrowser.open_new_tab(link):
        console.error(
            "Can't open link in the default browser. Try adding path and args for your browser to the config file."
        )
