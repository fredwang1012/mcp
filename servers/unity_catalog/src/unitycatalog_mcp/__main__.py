#!/usr/bin/env python3
"""
Entry point for unitycatalog_mcp server.
Parses --schema/-s and --genie-space-ids/-g via pydantic-settings,
then launches Uvicorn programmatically so that custom flags
aren't swallowed by Uvicorn's CLI.
"""
import uvicorn
from .cli import get_settings
# import src.unitycatalog_mcp.cli as cli_mod


def main():
    # Parse CLI args into a CliSettings instance
    # settings = get_settings()

    # Monkey-patch get_settings() so the server code sees these values
    # cli_mod.get_settings = lambda: settings

    # Launch Uvicorn programmatically (no CLI flag conflicts)
    uvicorn.run(
        "src.unitycatalog_mcp.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()
