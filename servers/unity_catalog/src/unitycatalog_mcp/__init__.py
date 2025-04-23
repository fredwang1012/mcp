import sys
from traceback import format_exc

from databricks.sdk.config import with_user_agent_extra
from unitycatalog_mcp.server import start
from unitycatalog_mcp.version import VERSION


def main() -> None:
    import asyncio

    with_user_agent_extra(key="unitycatalog-mcp", value=VERSION)
    asyncio.run(start())


if __name__ == "__main__":
    try:
        main()
    except Exception as _:
        print(format_exc(), file=sys.stderr)
