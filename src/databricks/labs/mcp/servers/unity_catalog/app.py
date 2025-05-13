from mcp.server import Server
from mcp.types import Tool as ToolSpec
import uvicorn
from databricks.labs.mcp.base import get_serveable_app
from databricks.labs.mcp.servers.unity_catalog.tools import (
    Content,
)
from databricks.labs.mcp.servers.unity_catalog.cli import get_settings

from databricks.labs.mcp._version import __version__ as VERSION
from databricks.labs.mcp.servers.unity_catalog.server import get_tools_dict


app = Server(name="mcp-unitycatalog", version=VERSION)
tools_dict = get_tools_dict(settings=get_settings())


@app.list_tools()
async def list_tools() -> list[ToolSpec]:
    return [tool.tool_spec for tool in tools_dict.values()]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[Content]:
    tool = tools_dict[name]
    return tool.execute(**arguments)


def start_app():
    serveable = get_serveable_app(app)
    uvicorn.run(serveable, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    start_app()
