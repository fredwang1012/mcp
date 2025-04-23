from typing import TypeAlias, Union

from unitycatalog_mcp.tools.functions import list_uc_function_tools
from unitycatalog_mcp.tools.genie import list_genie_tools
from unitycatalog_mcp.tools.vector_search import list_vector_search_tools

from mcp.types import (
    EmbeddedResource,
    ImageContent,
    TextContent,
)

Content: TypeAlias = Union[TextContent, ImageContent, EmbeddedResource]


def list_all_tools(settings):
    return list_genie_tools(settings) + list_vector_search_tools(settings) + list_uc_function_tools(settings)
