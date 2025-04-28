from typing import TypeAlias, Union
from mcp.types import (
    TextContent,
    ImageContent,
    EmbeddedResource,
)

from .genie import list_genie_tools
from .functions import list_uc_function_tools
from .vector_search import list_vector_search_tools

Content: TypeAlias = Union[TextContent, ImageContent, EmbeddedResource]


def list_all_tools(settings):
    return (
        list_genie_tools(settings)
        + list_vector_search_tools(settings)
        + list_uc_function_tools(settings)
    )
