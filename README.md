# Databricks Unity Catalog MCP Server

A Model Context Protocol (MCP) server that enables LLMs to query Unity Catalog on Databricks with user-specific permissions.

## Overview

This MCP server is deployed on Databricks Apps and provides:
- **SQL Query Execution**: Execute SQL queries against Unity Catalog
- **Table Discovery**: List available catalogs, schemas, and tables based on user permissions
- **Authentication**: Integrates with Databricks authentication to respect user privileges

## Deployment

The server is deployed at: https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com

## Features

- `execute_sql_query` tool - Run SQL queries against Unity Catalog
- `unity-catalog://tables` resource - Discover available tables and views
- Automatic authentication via Databricks Apps
- Permission-based access control

## Usage with Claude Desktop/Cline

Configure in your MCP settings:

```json
{
  "mcpServers": {
    "databricks-unity-catalog": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-http-client", 
               "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/mcp"],
      "env": {
        "AUTH_TYPE": "oauth2"
      }
    }
  }
}
```

## Development

The server code is in the `databricks-mcp-server/` directory.

To deploy updates:
```bash
databricks sync databricks-mcp-server "/Users/frederick.wang@bci.ca/databricks-mcp-server"
databricks apps deploy databricks-mcp-server --source-code-path "/Workspace/Users/frederick.wang@bci.ca/databricks-mcp-server"
```

## Architecture

- Built with FastAPI and FastMCP
- Deployed on Databricks Apps
- Uses Databricks SDK for Unity Catalog access
- Implements MCP protocol for LLM integration
