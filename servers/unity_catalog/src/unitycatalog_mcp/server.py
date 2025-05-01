import logging
import collections
import os

from mcp.server import NotificationOptions, Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import FileResponse

from unitycatalog_mcp.cli import get_settings
from unitycatalog_mcp.tools.base_tool import BaseTool
from unitycatalog_mcp.tools import list_all_tools, Content
from unitycatalog_mcp.version import VERSION

LOGGER = logging.getLogger(__name__)


def _warn_if_duplicate_tool_names(tools: list[BaseTool]):
    tool_names = [tool.tool_spec.name for tool in tools]
    duplicates = [
        name for name, cnt in collections.Counter(tool_names).items() if cnt > 1
    ]
    if duplicates:
        LOGGER.warning(
            f"Duplicate tool names detected: {duplicates}. Picking one per name."
        )


def get_tools_dict(settings) -> dict[str, BaseTool]:
    all_tools = list_all_tools(settings=settings)
    _warn_if_duplicate_tool_names(all_tools)
    # build dict once
    return {tool.tool_spec.name: tool for tool in all_tools}


# ────── Instantiate MCP server + tools ──────
settings = get_settings()
tools_dict = get_tools_dict(settings)
server = Server(name="mcp-unitycatalog", version=VERSION)


@server.list_tools()
async def list_tools() -> list[BaseTool]:
    return [tool.tool_spec for tool in tools_dict.values()]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[Content]:
    tool = tools_dict[name]
    return tool.execute(**arguments)


options = server.create_initialization_options(
    notification_options=NotificationOptions(
        resources_changed=True,
        tools_changed=True,
    )
)

# ────── SSE transport setup ──────
sse = SseServerTransport("/messages")


async def handle_sse(scope, receive, send):
    # this opens the SSE stream at POST /sse
    async with sse.connect_sse(scope, receive, send) as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)


async def handle_messages(scope, receive, send):
    # this handles POST /messages from the client
    await sse.handle_post_message(scope, receive, send)


def create_starlette_app(debug: bool = False) -> Starlette:
    """Create a Starlette application that can server the provied mcp server with SSE."""
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,  # noqa: SLF001
        ) as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    return Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["POST", "GET"]),
            Mount("/messages/", app=sse.handle_post_message),
            Route(
                "/",
                endpoint=lambda request: FileResponse(
                    os.path.join(os.path.dirname(__file__), "static", "index.html")
                ),
            ),
        ],
    )


# ────── Expose as ASGI app ──────
app = create_starlette_app()
