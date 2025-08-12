# Databricks Unity Catalog MCP Server for Claude Desktop

A Model Context Protocol (MCP) server that enables Claude Desktop to interact with Databricks Unity Catalog using natural language queries.

## Features

- **List Catalogs**: Browse all available Unity Catalog catalogs
- **List Schemas**: Explore schemas within specific catalogs
- **List Tables**: View tables in any schema
- **Describe Tables**: Get detailed table metadata including columns and types
- **Execute SQL**: Run SQL queries directly against Unity Catalog
- **Search Tables**: Find tables by name pattern within catalogs

## Architecture

```
Claude Desktop <-> MCP Client (Node.js) <-> Databricks Apps <-> Unity Catalog
```

- **MCP Client**: Local Node.js bridge (`databricks_mcp_client.js`)
- **Databricks Apps Server**: Python FastAPI server hosted on Databricks
- **Unity Catalog**: Your Databricks data catalog

## Prerequisites

1. **Node.js** installed on your local machine
2. **Databricks workspace** with Unity Catalog enabled
3. **Databricks Apps** access
4. **Claude Desktop** application
5. **SQL Warehouse** in Databricks

## Installation

### Step 1: Deploy the Server to Databricks Apps

1. Clone the repository:
```bash
git clone <repository-url>
cd databricks-mcp-server
```

2. Configure Databricks CLI:
```bash
databricks configure
```

3. Sync files to Databricks workspace:
```bash
databricks sync . //Workspace/Users/<your-email>/databricks-mcp-server
```

4. Deploy to Databricks Apps:
```bash
databricks apps deploy databricks-mcp-server
```

Your server will be available at:
`https://databricks-mcp-server-<workspace-id>.azure.databricksapps.com`

### Step 2: Set Up Local MCP Client

1. Copy the MCP client to your local directory:
```bash
mkdir C:\Users\<YourName>\mcp
copy databricks_mcp_client.js C:\Users\<YourName>\mcp\
```

2. Update the client with your server URL:
Edit `databricks_mcp_client.js` and set:
```javascript
const SERVER_URL = 'https://databricks-mcp-server-<workspace-id>.azure.databricksapps.com/mcp';
```

### Step 3: Get Authentication Token

You need a Databricks token with SQL scopes. Visit your deployed app's homepage to get instructions on obtaining a token.

**Required Scopes:**
- `sql` - Execute SQL queries
- `catalog.connections` - Access Unity Catalog (optional)
- `iam.current-user:read` - User identity
- `iam.access-control:read` - Access control

### Step 4: Configure Claude Desktop

1. Open Claude Desktop configuration:
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`

2. Add the MCP server configuration:
```json
{
  "mcpServers": {
    "unity-catalog": {
      "command": "node",
      "args": [
        "C:\\Users\\<YourName>\\mcp\\databricks_mcp_client.js"
      ],
      "env": {
        "BEARER_TOKEN": "YOUR_BEARER_TOKEN_HERE"
      }
    }
  }
}
```

3. Restart Claude Desktop

## Usage Examples

Once configured, you can ask Claude natural language questions about your data:

### Basic Queries
- "Show me all available catalogs"
- "List the schemas in the samples catalog"
- "What tables are in samples.nyctaxi?"
- "Describe the structure of samples.nyctaxi.trips"

### SQL Queries
- "Run a SQL query to get 10 rows from samples.nyctaxi.trips"
- "Show me the average fare by hour of day"
- "What are the top 10 pickup locations by trip count?"

### Complex Analysis
```
"Analyze the NYC taxi data:
1. Show summary statistics
2. Find peak hours
3. Calculate average fare per mile
4. Show busiest pickup locations"
```

## Troubleshooting

### Token Expired
Tokens expire after 1 hour. Get a new token from your Databricks workspace and update `claude_desktop_config.json`.

### Connection Issues
1. Check that your Databricks Apps server is running:
```bash
databricks apps list
```

2. Verify the server URL in `databricks_mcp_client.js`

3. Check Claude logs:
   - Windows: `%APPDATA%\Claude\logs\mcp-server-unity-catalog.log`

### SQL Errors
Ensure your token has the `sql` scope and you have access to the SQL warehouse configured in the server.

## Architecture Details

### MCP Client (`databricks_mcp_client.js`)
- Handles JSON-RPC communication between Claude and Databricks
- Manages authentication tokens
- Routes requests to Databricks Apps server

### Databricks Apps Server (`src/custom_server/app.py`)
- FastAPI application hosted on Databricks
- Implements MCP protocol handlers
- Executes SQL queries via Databricks SDK
- Manages user authentication

### Supported MCP Methods
- `initialize` - Protocol handshake
- `tools/list` - List available tools
- `tools/call` - Execute tool functions
- `resources/list` - List resources (empty)
- `prompts/list` - List prompts (empty)

## Security

- Tokens are stored locally in Claude's configuration
- Server runs in your Databricks workspace with your permissions
- All queries execute with the authenticated user's access rights
- No data is stored or cached outside Databricks

## Development

### Local Testing
```bash
# Test the client directly
node databricks_mcp_client.js

# Check server logs
databricks apps logs databricks-mcp-server
```

### Updating the Server
```bash
# Make changes to the code
cd databricks-mcp-server

# Sync to Databricks
databricks sync . //Workspace/Users/<your-email>/databricks-mcp-server

# Deploy
databricks apps deploy databricks-mcp-server
```

## License

MIT

## Support

For issues or questions, please open an issue on GitHub.