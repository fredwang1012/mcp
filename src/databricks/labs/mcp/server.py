from contextlib import AsyncExitStack
from typing import Any
import anyio
from mcp.server.fastmcp.server import FastMCP, Settings, lifespan_wrapper, Context
from mcp.server.lowlevel.server import lifespan as default_lifespan
from mcp.server.lowlevel import Server
from pydantic import BaseModel
from pydantic import BaseModel, SecretStr, EmailStr
import logging
from starlette.applications import Starlette
from starlette.requests import Request
from mcp.server.sse import SseServerTransport
from starlette.routing import Mount, Route
from mcp.server.fastmcp.prompts import PromptManager
from mcp.server.fastmcp.resources import ResourceManager
from mcp.server.fastmcp.tools import ToolManager
from mcp.server.fastmcp.utilities.logging import configure_logging
from mcp.server.models import InitializationOptions
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server.session import ServerSession
from starlette.responses import HTMLResponse

import mcp.types as types


def get_logger():
    logger = logging.getLogger("databricks.labs.mcp")
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = get_logger()


class UserInfo(BaseModel):
    email: EmailStr
    token: SecretStr  # This hides the token in repr and logs


class SessionWithHeaders(ServerSession):
    def __init__(self, *args, **kwargs):

        logger.info("Initializing the session")
        if "headers" in kwargs:
            self.headers = kwargs.pop("headers")
            logger.debug(f"Session header keys: {self.headers.keys()}")
            logger.debug(f"Session headers: {self.headers}")
        else:
            self.headers = {}
            logger.warning("No headers provided for session")

        super().__init__(*args, **kwargs)


class ServerWithHeaders(Server):

    async def run(
        self,
        read_stream: MemoryObjectReceiveStream[types.JSONRPCMessage | Exception],
        write_stream: MemoryObjectSendStream[types.JSONRPCMessage],
        initialization_options: InitializationOptions,
        # When False, exceptions are returned as messages to the client.
        # When True, exceptions are raised, which will cause the server to shut down
        # but also make tracing exceptions much easier during testing and when using
        # in-process servers.
        raise_exceptions: bool = False,
        headers: dict[str, str] | None = None,
    ):
        async with AsyncExitStack() as stack:
            lifespan_context = await stack.enter_async_context(self.lifespan(self))
            session = await stack.enter_async_context(
                SessionWithHeaders(
                    read_stream, write_stream, initialization_options, headers=headers
                )
            )

            async with anyio.create_task_group() as tg:
                async for message in session.incoming_messages:
                    logger.debug(f"Received message: {message}")

                    tg.start_soon(
                        self._handle_message,
                        message,
                        session,
                        lifespan_context,
                        raise_exceptions,
                    )


class DatabricksMCP(FastMCP):

    def __init__(
        self, name: str | None = None, instructions: str | None = None, **settings: Any
    ):
        self.settings = Settings(**settings)

        self._mcp_server = ServerWithHeaders(
            name=name or "FastMCP",
            instructions=instructions,
            lifespan=(
                lifespan_wrapper(self, self.settings.lifespan)
                if self.settings.lifespan
                else default_lifespan
            ),
        )
        self._tool_manager = ToolManager(
            warn_on_duplicate_tools=self.settings.warn_on_duplicate_tools
        )
        self._resource_manager = ResourceManager(
            warn_on_duplicate_resources=self.settings.warn_on_duplicate_resources
        )
        self._prompt_manager = PromptManager(
            warn_on_duplicate_prompts=self.settings.warn_on_duplicate_prompts
        )
        self.dependencies = self.settings.dependencies

        # Set up MCP protocol handlers
        self._setup_handlers()

        # Configure logging
        configure_logging(self.settings.log_level)

    def sse_app(self) -> Starlette:
        """Return an instance of the SSE server app."""
        sse = SseServerTransport(self.settings.message_path)

        async def handle_sse(request: Request) -> None:
            async with sse.connect_sse(
                request.scope,
                request.receive,
                request._send,  # type: ignore[reportPrivateUsage]
            ) as streams:

                await self._mcp_server.run(
                    streams[0],
                    streams[1],
                    self._mcp_server.create_initialization_options(),
                    headers=request.headers,
                )

        return Starlette(
            debug=self.settings.debug,
            routes=[
                Route(self.settings.sse_path, endpoint=handle_sse),
                Mount(self.settings.message_path, app=sse.handle_post_message),
            ],
        )

    def get_context(self) -> Context[SessionWithHeaders, object]:
        """
        Returns a Context object. Note that the context will only be valid
        during a request; outside a request, most methods will error.
        """
        try:
            request_context = self._mcp_server.request_context
        except LookupError:
            request_context = None
        return Context(request_context=request_context, fastmcp=self)

    def get_current_user(self) -> UserInfo | None:
        """
        Returns the current user from the context.
        """
        session = self.get_context().session
        if session is None:
            return None

        email = session.headers.get("x-forwarded-email")

        if email:
            token = session.headers.get("x-forwarded-access-token")
            if token:
                return UserInfo(email=email, token=SecretStr(token))
            else:
                logger.warning("No token found in headers")

        return None
