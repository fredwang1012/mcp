# Databricks MCP Server for Claude Desktop

This project provides a Model Context Protocol (MCP) server that connects Claude Desktop to Databricks Unity Catalog, allowing you to query databases, list catalogs, tables, and schemas directly from Claude.

## Architecture

The setup consists of three main components:

1. **Claude Desktop** - The AI assistant interface
2. **MCP Client** (`databricks_mcp_client.js`) - Bridge between Claude and Databricks Apps
3. **MCP Server** (`databricks-mcp-server/`) - FastAPI server deployed on Databricks Apps

## Prerequisites

- Claude Desktop installed
- Databricks workspace access
- Databricks CLI configured
- Node.js installed
- Access to Databricks Apps

## Setup Instructions

### 1. Configure Databricks CLI

```bash
databricks configure
```

Set your workspace host and token:
- Host: `https://your-workspace.databricks.com`
- Token: Your personal access token

### 2. Deploy the MCP Server

```bash
cd databricks-mcp-server
databricks sync . //Workspace/Users/your-email@domain.com/databricks-mcp-server --full
databricks apps deploy databricks-mcp-server
```

### 3. Get MCP Client and Configure Claude Desktop

1. Visit your deployed app dashboard: `https://your-app.databricksapps.com`
2. Click the **"💾 Download Client"** button to download `databricks_mcp_client.js`
3. Save the file to a permanent location, for example:
   - Windows: `C:\Users\YourName\mcp\databricks_mcp_client.js`
   - Mac: `~/mcp/databricks_mcp_client.js`
   - Linux: `~/mcp/databricks_mcp_client.js`
4. The dashboard will show your Claude Desktop configuration with:
   - The correct file path format for your OS
   - Your current authentication token (auto-refreshed)
5. Click **"📋 Copy Configuration"** to copy the entire config
6. Note: Tokens expire every hour - revisit the dashboard to get a fresh token

### 4. Configure Claude Desktop

Update your Claude Desktop configuration file:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "unity-catalog": {
      "command": "node",
      "args": ["C:\\path\\to\\your\\databricks_mcp_client.js"],
      "env": {
        "BEARER_TOKEN": "your-jwt-token-from-dashboard"
      }
    }
  }
}
```

Replace `C:\\path\\to\\your\\databricks_mcp_client.js` with the actual path where you saved the file.

### 5. Restart Claude Desktop

Close and reopen Claude Desktop to load the new configuration.

## Usage

Once configured, you can ask Claude to:

- List all catalogs: "Show me all available catalogs"
- List schemas: "What schemas are in the main catalog?"
- List tables: "Show me tables in the default schema"
- Query data: "Get the first 10 rows from table_name"
- Explore data structure: "Describe the schema of table_name"

## Troubleshooting

### Token Expiration
If you get authentication errors, refresh your JWT token:
1. Visit your app URL in browser
2. Extract fresh token from cookies
3. Update `claude_desktop_config.json`
4. Restart Claude Desktop

### Connection Issues
Check the Claude Desktop logs at `%APPDATA%\Claude\logs\`:
- `mcp-server-unity-catalog.log` - MCP server connection logs
- `mcp.log` - General MCP logs

### Server Logs
Monitor Databricks Apps logs:
```bash
databricks apps list-deployments your-app-name
```

## Files Structure

```
mcp/
├── databricks_mcp_client.js     # MCP client (bridge)
├── databricks-mcp-server/       # Main server code
│   ├── src/custom_server/
│   │   ├── app.py              # FastAPI MCP server
│   │   └── main.py             # Entry point
│   ├── databricks.yml          # Deployment config
│   └── requirements.txt        # Python dependencies
└── README.md                    # This file
```

## Authentication Flow

1. Claude Desktop → MCP Client (via stdio)
2. MCP Client → Databricks Apps (HTTP with Bearer token)
3. Databricks Apps → Unity Catalog APIs (authenticated requests)
4. Results flow back through the chain to Claude

## Security Notes

- **User Isolation**: The server uses Databricks Apps' `x-forwarded-access-token` header to authenticate users
- **Permission Enforcement**: Users can only access Unity Catalog resources they have permissions for
- **Token Security**: JWT tokens expire every hour and need refreshing
- **No Credential Storage**: Never commit tokens to version control
- **Environment Variables**: Use environment variables for sensitive configuration
- **Access Control**: The MCP server enforces the same permissions as your Databricks workspace access