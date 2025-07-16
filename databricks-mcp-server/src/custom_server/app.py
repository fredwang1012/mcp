import time
print("🚀 Unity Catalog MCP Server - VERSION 7.5 SQL-ONLY")
print("✅ All tools now use SQL instead of SDK calls!")
print("✅ Fixed authentication mismatch with Databricks Apps!")
print(f"🕒 Server starting at {time.strftime('%Y-%m-%d %H:%M:%S')}")
print("📍 File path: src/custom_server/app.py")

import asyncio
import json
import os
from typing import Any, Dict, List
from pathlib import Path
from datetime import datetime, timedelta, timezone
import pytz

import jwt
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from databricks.sdk import WorkspaceClient

# Official MCP SDK imports
from mcp.server import Server
from mcp.types import Tool, TextContent, CallToolRequest, CallToolResult
import mcp.server.stdio

# =============================================
# DATABRICKS CONFIGURATION
# =============================================

DATABRICKS_HOST = os.environ.get('DATABRICKS_HOST', 'https://adb-1761712055023179.19.azuredatabricks.net')
DATABRICKS_WAREHOUSE_ID = os.environ.get('DATABRICKS_WAREHOUSE_ID', 'a85c850e7621e163')

print(f"🔧 Databricks Host: {DATABRICKS_HOST}")
print(f"🔧 Warehouse ID: {DATABRICKS_WAREHOUSE_ID}")

# =============================================
# TOKEN MANAGER
# =============================================

class TokenManager:
    def __init__(self):
        self.current_token = None
        self.token_expiry = None
        self.last_update = None
        self.pst = pytz.timezone('America/Los_Angeles')
        
    def update_token_from_request(self, request):
        """Update token from request headers"""
        # Try Authorization header first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            self.set_token(token)
            return True
            
        # Try x-forwarded-access-token header
        forwarded_token = request.headers.get("x-forwarded-access-token", "")
        if forwarded_token and forwarded_token != "not found":
            self.set_token(forwarded_token)
            return True
            
        return False
        
    def set_token(self, token):
        """Set current token and decode expiry"""
        if token == self.current_token:
            return  # No change
            
        self.current_token = token
        self.last_update = datetime.now(self.pst)
        
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            # JWT exp is in UTC seconds since epoch - convert to PST
            utc_expiry = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            self.token_expiry = utc_expiry.astimezone(self.pst)
            print(f"🔍 Token expires at: {self.token_expiry} PST (UTC: {utc_expiry})")
        except Exception as e:
            print(f"❌ Error decoding token: {e}")
            self.token_expiry = None
            
    def get_status(self):
        """Get current token status"""
        if not self.current_token or not self.token_expiry:
            return {
                "status": "no_token",
                "message": "No token available",
                "token": None,
                "minutes_left": 0,
                "expires_at": None,
                "last_update": None
            }
            
        now = datetime.now(self.pst)
        time_left = self.token_expiry - now
        total_seconds = max(0, int(time_left.total_seconds()))
        minutes_left = total_seconds // 60
        
        print(f"🔍 Time calculation PST: now={now}, expiry={self.token_expiry}, minutes={minutes_left}")
        
        if total_seconds <= 0:
            status = "expired"
            message = "Token has expired"
        elif minutes_left <= 10:
            status = "expiring_soon"
            message = f"Token expires in {minutes_left} minutes"
        else:
            status = "valid"
            message = f"Token is valid for {minutes_left} minutes"
            
        return {
            "status": status,
            "message": message,
            "token": self.current_token,
            "minutes_left": minutes_left,
            "expires_at": self.token_expiry.isoformat(),
            "last_update": self.last_update.isoformat() if self.last_update else None
        }
        
    def get_claude_config(self):
        """Get Claude Desktop configuration"""
        if not self.current_token:
            return None
            
        return {
            "mcpServers": {
                "unity-catalog": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-fetch", "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/mcp"],
                    "env": {
                        "BEARER_TOKEN": self.current_token
                    }
                }
            }
        }

# Create global token manager instance
token_manager = TokenManager()

# =============================================
# DATABRICKS CLIENT
# =============================================

def get_databricks_client():
    """Get authenticated Databricks client"""
    try:
        client = WorkspaceClient()
        return client
    except Exception as e:
        print(f"❌ Error initializing Databricks client: {e}")
        return None

# =============================================
# SQL EXECUTION HELPER
# =============================================

def execute_sql_query(client, query):
    """Execute SQL query using the same method that works for permissions"""
    try:
        print(f"🔍 Executing SQL: {query}")
        result = client.statement_execution.execute_statement(
            statement=query,
            warehouse_id=DATABRICKS_WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        if result.result and result.result.data_array:
            print(f"✅ SQL Success: {len(result.result.data_array)} rows returned")
            return result.result.data_array
        else:
            print("✅ SQL Success: No data returned")
            return []
    except Exception as e:
        print(f"❌ SQL Error: {str(e)}")
        raise Exception(f"SQL execution failed: {str(e)}")

# =============================================
# HELPER FUNCTIONS
# =============================================

def safe_datetime_format(dt_value):
    """Safely format datetime values to ISO format"""
    if dt_value is None:
        return None
    
    # If it's already a string, return as is
    if isinstance(dt_value, str):
        return dt_value
    
    # If it's a datetime object, format it
    if hasattr(dt_value, 'isoformat'):
        return dt_value.isoformat()
    
    # If it's a number (Unix timestamp), convert to datetime first
    if isinstance(dt_value, (int, float)):
        try:
            return datetime.fromtimestamp(dt_value / 1000 if dt_value > 1e10 else dt_value).isoformat()
        except (ValueError, OSError):
            return str(dt_value)
    
    # Default: convert to string
    return str(dt_value) if dt_value is not None else None

def safe_get_attribute(obj, attr_name, default=None):
    """Safely get attribute from object, return default if not exists"""
    return getattr(obj, attr_name, default)

# =============================================
# MCP SERVER SETUP
# =============================================

# Create official MCP server
server = Server("unity-catalog-mcp")
print("✅ Official MCP server created!")

# =============================================
# MCP TOOLS
# =============================================

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="query_sql",
            description="Execute SQL query against Unity Catalog",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "SQL query to execute"}
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="list_catalogs",
            description="List all available catalogs in Unity Catalog",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="list_schemas",
            description="List schemas in a specific catalog",
            inputSchema={
                "type": "object",
                "properties": {
                    "catalog_name": {"type": "string", "description": "Name of the catalog"}
                },
                "required": ["catalog_name"]
            }
        ),
        Tool(
            name="list_tables",
            description="List tables in a specific schema",
            inputSchema={
                "type": "object",
                "properties": {
                    "catalog_name": {"type": "string", "description": "Name of the catalog"},
                    "schema_name": {"type": "string", "description": "Name of the schema"}
                },
                "required": ["catalog_name", "schema_name"]
            }
        ),
        Tool(
            name="describe_table",
            description="Get detailed information about a specific table",
            inputSchema={
                "type": "object",
                "properties": {
                    "catalog_name": {"type": "string", "description": "Name of the catalog"},
                    "schema_name": {"type": "string", "description": "Name of the schema"},
                    "table_name": {"type": "string", "description": "Name of the table"}
                },
                "required": ["catalog_name", "schema_name", "table_name"]
            }
        ),
        Tool(
            name="search_tables",
            description="Search for tables matching a query in a catalog",
            inputSchema={
                "type": "object",
                "properties": {
                    "catalog_name": {"type": "string", "description": "Name of the catalog"},
                    "query": {"type": "string", "description": "Search query"}
                },
                "required": ["catalog_name", "query"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
    """Handle tool calls using SQL for everything"""
    try:
        client = get_databricks_client()
        if not client:
            return CallToolResult(
                content=[TextContent(type="text", text="❌ Error: Unable to connect to Databricks")]
            )
        
        if name == "query_sql":
            query = arguments.get("query", "")
            if not query:
                return CallToolResult(
                    content=[TextContent(type="text", text="❌ Error: query is required")]
                )
            
            try:
                results = execute_sql_query(client, query)
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Query executed successfully. Results: {json.dumps(results, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ SQL execution failed: {str(e)}")]
                )
        
        elif name == "list_catalogs":
            try:
                # Use SQL instead of SDK
                results = execute_sql_query(client, "SHOW CATALOGS")
                catalog_names = [row[0] for row in results]  # First column contains catalog names
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Available catalogs: {json.dumps(catalog_names, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ Error listing catalogs: {str(e)}")]
                )
        
        elif name == "list_schemas":
            catalog_name = arguments.get("catalog_name", "")
            if not catalog_name:
                return CallToolResult(
                    content=[TextContent(type="text", text="❌ Error: catalog_name is required")]
                )
            
            try:
                # Use SQL instead of SDK
                query = f"SHOW SCHEMAS IN {catalog_name}"
                results = execute_sql_query(client, query)
                schema_names = [row[0] for row in results]  # First column contains schema names
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Schemas in catalog '{catalog_name}': {json.dumps(schema_names, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ Error listing schemas: {str(e)}")]
                )
        
        elif name == "list_tables":
            catalog_name = arguments.get("catalog_name", "")
            schema_name = arguments.get("schema_name", "")
            
            if not catalog_name or not schema_name:
                return CallToolResult(
                    content=[TextContent(type="text", text="❌ Error: catalog_name and schema_name are required")]
                )
            
            try:
                # Use SQL instead of SDK
                query = f"SHOW TABLES IN {catalog_name}.{schema_name}"
                results = execute_sql_query(client, query)
                table_names = [row[0] for row in results]  # First column contains table names
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Tables in schema '{catalog_name}.{schema_name}': {json.dumps(table_names, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ Error listing tables: {str(e)}")]
                )
        
        elif name == "describe_table":
            catalog_name = arguments.get("catalog_name", "")
            schema_name = arguments.get("schema_name", "")
            table_name = arguments.get("table_name", "")
            
            if not catalog_name or not schema_name or not table_name:
                return CallToolResult(
                    content=[TextContent(type="text", text="❌ Error: catalog_name, schema_name, and table_name are required")]
                )
            
            try:
                # Use SQL instead of SDK
                full_table_name = f"{catalog_name}.{schema_name}.{table_name}"
                
                # Get table description
                describe_query = f"DESCRIBE TABLE {full_table_name}"
                describe_results = execute_sql_query(client, describe_query)
                
                # Parse column information
                columns = []
                for row in describe_results:
                    if len(row) >= 2:  # At least column name and type
                        columns.append({
                            "name": row[0],
                            "type": row[1],
                            "comment": row[2] if len(row) > 2 and row[2] else None
                        })
                
                # Get table properties
                table_info = {
                    "name": table_name,
                    "catalog": catalog_name,
                    "schema": schema_name,
                    "full_name": full_table_name,
                    "columns": columns,
                    "column_count": len(columns)
                }
                
                # Try to get additional table information
                try:
                    detail_query = f"DESCRIBE DETAIL {full_table_name}"
                    detail_results = execute_sql_query(client, detail_query)
                    if detail_results and len(detail_results) > 0:
                        # Detail results vary, but typically have format, size, etc.
                        detail_row = detail_results[0]
                        if len(detail_row) > 5:  # If we have detailed info
                            table_info["table_format"] = detail_row[0] if len(detail_row) > 0 else None
                            table_info["location"] = detail_row[1] if len(detail_row) > 1 else None
                            table_info["size_bytes"] = detail_row[2] if len(detail_row) > 2 else None
                            table_info["created_at"] = detail_row[3] if len(detail_row) > 3 else None
                except Exception as detail_error:
                    # If DESCRIBE DETAIL fails, continue without detailed info
                    print(f"⚠️ Could not get detailed table info: {detail_error}")
                
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Table details: {json.dumps(table_info, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ Error describing table: {str(e)}")]
                )
        
        elif name == "search_tables":
            catalog_name = arguments.get("catalog_name", "")
            search_query = arguments.get("query", "")
            
            if not catalog_name or not search_query:
                return CallToolResult(
                    content=[TextContent(type="text", text="❌ Error: catalog_name and query are required")]
                )
            
            try:
                # First get all schemas in the catalog
                schemas_query = f"SHOW SCHEMAS IN {catalog_name}"
                schema_results = execute_sql_query(client, schemas_query)
                schema_names = [row[0] for row in schema_results]
                
                matching_tables = []
                
                for schema_name in schema_names:
                    try:
                        # Get tables in this schema
                        tables_query = f"SHOW TABLES IN {catalog_name}.{schema_name}"
                        table_results = execute_sql_query(client, tables_query)
                        
                        for table_row in table_results:
                            table_name = table_row[0]
                            # Search for matching table names
                            if search_query.lower() in table_name.lower():
                                matching_tables.append({
                                    "full_name": f"{catalog_name}.{schema_name}.{table_name}",
                                    "name": table_name,
                                    "schema": schema_name,
                                    "catalog": catalog_name
                                })
                    except Exception as schema_error:
                        # Skip schemas we can't access
                        print(f"⚠️ Could not access schema {schema_name}: {schema_error}")
                        continue
                
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Found {len(matching_tables)} tables matching '{search_query}': {json.dumps(matching_tables, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ Error searching tables: {str(e)}")]
                )
        
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"❌ Unknown tool: {name}")]
            )
    
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"❌ Error executing tool {name}: {str(e)}")]
        )

print("✅ MCP tools registered successfully!")

# =============================================
# FASTAPI SETUP
# =============================================

app = FastAPI(
    title="Unity Catalog MCP Server",
    description="MCP server for Unity Catalog integration using SQL only",
    version="7.5",
    redirect_slashes=False
)

# Add proxy headers middleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["*"])

print("✅ FastAPI app created!")

# =============================================
# DASHBOARD AT ROOT
# =============================================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Clean and fast dashboard for token management"""
    
    # Update token from request
    token_manager.update_token_from_request(request)
    
    # Get current status
    status = token_manager.get_status()
    config = token_manager.get_claude_config()
    
    # Use the token manager's calculation - it's already correct in PST
    minutes_left = status['minutes_left']
    seconds_left = 0
    
    # Get current PST time for display
    pst = pytz.timezone('America/Los_Angeles')
    current_pst = datetime.now(pst)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unity Catalog MCP Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: system-ui, -apple-system, sans-serif;
            background: #f5f7fa;
            padding: 20px;
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2rem;
        }}
        
        .header p {{
            color: #7f8c8d;
            font-size: 1.1rem;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}
        
        .card-title {{
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 15px;
            color: #2c3e50;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .status-indicator {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
        }}
        
        .status-valid {{ background: #d4edda; color: #155724; }}
        .status-expiring {{ background: #fff3cd; color: #856404; }}
        .status-expired {{ background: #f8d7da; color: #721c24; }}
        .status-no-token {{ background: #e2e3e5; color: #383d41; }}
        
        .status-icon {{
            font-size: 1.5rem;
        }}
        
        .countdown {{
            font-size: 2rem;
            font-weight: 700;
            text-align: center;
            margin: 15px 0;
            color: #2c3e50;
            font-family: monospace;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 15px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }}
        
        .progress-valid {{ background: #28a745; }}
        .progress-expiring {{ background: #ffc107; }}
        .progress-expired {{ background: #dc3545; }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin: 15px 0;
        }}
        
        .info-item {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
        }}
        
        .info-label {{
            font-size: 0.9rem;
            color: #6c757d;
            margin-bottom: 5px;
        }}
        
        .info-value {{
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .code-block {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            font-family: monospace;
            font-size: 0.9rem;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .btn {{
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }}
        
        .btn:hover {{
            background: #0056b3;
        }}
        
        .btn-success {{
            background: #28a745;
        }}
        
        .btn-success:hover {{
            background: #1e7e34;
        }}
        
        .btn-danger {{
            background: #dc3545;
        }}
        
        .btn-danger:hover {{
            background: #c82333;
        }}
        
        .btn-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin: 15px 0;
        }}
        
        .instructions {{
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 5px 5px 0;
        }}
        
        .instructions h3 {{
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        
        .instructions ol, .instructions ul {{
            margin-left: 20px;
        }}
        
        .instructions li {{
            margin: 5px 0;
        }}
        
        .notification {{
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 5px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            opacity: 0;
            transition: opacity 0.3s ease;
        }}
        
        .notification.show {{
            opacity: 1;
        }}
        
        .notification-success {{
            background: #28a745;
        }}
        
        .notification-error {{
            background: #dc3545;
        }}
        
        .auto-refresh {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #6c757d;
            color: white;
            padding: 8px 12px;
            border-radius: 5px;
            font-size: 0.9rem;
        }}
        
        .version-badge {{
            background: #17a2b8;
            color: white;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.8rem;
            margin-left: 10px;
        }}
        
        @media (max-width: 768px) {{
            .grid {{
                grid-template-columns: 1fr;
            }}
            
            .info-grid {{
                grid-template-columns: 1fr;
            }}
            
            .btn-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 1.5rem;
            }}
            
            .countdown {{
                font-size: 1.5rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Unity Catalog MCP Dashboard <span class="version-badge">v7.5 SQL-Only</span></h1>
            <p>Token Management & Claude Desktop Configuration</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <div class="card-title">
                    <span>📊</span> Token Status
                </div>
                
                <div class="status-indicator status-{status['status']}">
                    <div class="status-icon">
                        {"✅" if status['status'] == 'valid' else "⚠️" if status['status'] == 'expiring_soon' else "❌" if status['status'] == 'expired' else "❓"}
                    </div>
                    <div>
                        <div id="statusMessage"><strong>{status['message']}</strong></div>
                        <div style="font-size: 0.9rem; margin-top: 5px;">
                            Last updated: {current_pst.strftime('%H:%M:%S')} PST
                        </div>
                    </div>
                </div>
                
                <div class="countdown" id="countdown">
                    {f"{minutes_left:02d}:{seconds_left:02d}"}
                </div>
                
                <div class="progress-bar">
                    <div class="progress-fill progress-{status['status']}" 
                         style="width: {max(0, min(100, (minutes_left / 60) * 100))}%"></div>
                </div>
                
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Status</div>
                        <div class="info-value">{status['status'].upper().replace('_', ' ')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Minutes Left</div>
                        <div class="info-value" id="minutesLeftValue">{minutes_left}</div>
                    </div>
                </div>
                
                <button class="btn btn-danger" onclick="refreshStatus()">🔄 Refresh Status</button>
            </div>
            
            <div class="card">
                <div class="card-title">
                    <span>🎯</span> Claude Desktop Configuration
                </div>
                
                <div class="code-block">{json.dumps(config, indent=2) if config else "No token available"}</div>
                
                <button class="btn btn-success" onclick="copyConfig()">📋 Copy Configuration</button>
                
                <div class="instructions">
                    <h3>📝 Setup Instructions:</h3>
                    <ol>
                        <li>Copy the configuration above</li>
                        <li>Open Claude Desktop settings.json</li>
                        <li>Replace the content with the copied configuration</li>
                        <li>Restart Claude Desktop</li>
                    </ol>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">
                    <span>🔑</span> Access Token
                </div>
                
                <div class="code-block">{status['token'][:50] + '...' if status['token'] else 'No token available'}</div>
                
                <button class="btn btn-success" onclick="copyToken()">📋 Copy Token</button>
                
                <div class="instructions">
                    <h3>🔄 Token Refresh:</h3>
                    <ol>
                        <li>Tokens expire every ~60 minutes</li>
                        <li>Visit this page to refresh automatically</li>
                        <li>When expired, just reload this page</li>
                    </ol>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">
                    <span>🛠️</span> Quick Actions
                </div>
                
                <div class="btn-grid">
                    <a href="/debug-headers" target="_blank" class="btn">🔍 Debug Headers</a>
                    <a href="/health" target="_blank" class="btn">❤️ Health Check</a>
                    <a href="/mcp" target="_blank" class="btn">🔗 MCP Endpoint</a>
                    <button class="btn" onclick="testConnection()">🧪 Test Connection</button>
                </div>
                
                <div class="instructions">
                    <h3>🚀 Available Tools (SQL-Only):</h3>
                    <ul>
                        <li>📊 Query SQL databases</li>
                        <li>📁 List catalogs and schemas</li>
                        <li>📋 List and describe tables</li>
                        <li>🔍 Search for tables</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <div class="auto-refresh">Auto-refresh: ON (60s)</div>
    
    <div class="notification" id="notification"></div>
    
    <script>
        let autoRefreshInterval;
        let countdownInterval;
        let expiryTime = "{status['expires_at'] or ''}";
        
        function showNotification(message, type = 'success') {{
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = `notification notification-${{type}}`;
            
            // Show notification with fade in
            notification.classList.add('show');
            
            // Hide after 3 seconds with fade out
            setTimeout(() => {{
                notification.classList.remove('show');
            }}, 3000);
        }}
        
        function copyToClipboard(text) {{
            if (navigator.clipboard) {{
                navigator.clipboard.writeText(text);
            }} else {{
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }}
        }}
        
        function copyToken() {{
            const token = "{status['token'] or ''}";
            if (token) {{
                copyToClipboard(token);
                showNotification('Token copied to clipboard!');
            }} else {{
                showNotification('No token available', 'error');
            }}
        }}
        
        function copyConfig() {{
            const config = `{json.dumps(config, indent=2) if config else ''}`;
            if (config && config !== 'null') {{
                copyToClipboard(config);
                showNotification('Configuration copied to clipboard!');
            }} else {{
                showNotification('No configuration available', 'error');
            }}
        }}
        
        function refreshStatus() {{
            window.location.reload();
        }}
        
        function testConnection() {{
            fetch('/health')
                .then(response => response.json())
                .then(data => {{
                    if (data.status === 'healthy') {{
                        showNotification('Connection successful!');
                    }} else {{
                        showNotification('Connection failed', 'error');
                    }}
                }})
                .catch(error => {{
                    showNotification('Connection error', 'error');
                }});
        }}
        
        function updateCountdown() {{
            if (!expiryTime) return;
            
            // Parse the PST time from server
            const expiry = new Date(expiryTime);
            const now = new Date();
            const timeLeft = Math.max(0, Math.floor((expiry - now) / 1000));
            
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            
            // Update countdown display
            document.getElementById('countdown').textContent = 
                `${{minutes.toString().padStart(2, '0')}}:${{seconds.toString().padStart(2, '0')}}`;
            
            // Update minutes left display
            const minutesLeftElement = document.getElementById('minutesLeftValue');
            if (minutesLeftElement) {{
                minutesLeftElement.textContent = minutes;
            }}
            
            // Update status message
            const statusMessageElement = document.getElementById('statusMessage');
            if (statusMessageElement && minutes > 0) {{
                if (minutes <= 10) {{
                    statusMessageElement.innerHTML = `<strong>Token expires in ${{minutes}} minutes</strong>`;
                }} else {{
                    statusMessageElement.innerHTML = `<strong>Token is valid for ${{minutes}} minutes</strong>`;
                }}
            }}
            
            // Update progress bar
            const progressFill = document.querySelector('.progress-fill');
            if (progressFill) {{
                const progressPercent = Math.max(0, Math.min(100, (minutes / 60) * 100));
                progressFill.style.width = progressPercent + '%';
            }}
            
            if (timeLeft <= 0) {{
                showNotification('Token has expired! Please refresh.', 'error');
                clearInterval(countdownInterval);
            }}
        }}
        
        // Initialize
        if (expiryTime) {{
            countdownInterval = setInterval(updateCountdown, 1000);
            updateCountdown();
        }}
        
        // Auto-refresh every 60 seconds
        autoRefreshInterval = setInterval(() => {{
            window.location.reload();
        }}, 60000);
    </script>
</body>
</html>
    """
    
    return HTMLResponse(content=html_content)

# =============================================
# API ENDPOINT FOR DASHBOARD DATA
# =============================================

@app.get("/api/dashboard-data")
async def dashboard_data(request: Request):
    """JSON API endpoint for dashboard data"""
    token_manager.update_token_from_request(request)
    status = token_manager.get_status()
    config = token_manager.get_claude_config()
    
    return {
        "status": status,
        "config": config,
        "server_info": {
            "version": "7.5",
            "name": "unity-catalog-mcp",
            "tools_count": 6,
            "endpoint": "/mcp",
            "approach": "sql_only"
        }
    }

# =============================================
# REGULAR ENDPOINTS
# =============================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "Unity Catalog MCP Server",
        "version": "7.5",
        "approach": "sql_only",
        "endpoint": "/mcp"
    }

@app.get("/debug-headers")
async def debug_headers(request: Request):
    """Debug endpoint to check headers"""
    headers = dict(request.headers)
    return {
        "message": "Headers received by Databricks App",
        "all_headers": headers,
        "important_headers": {
            "host": headers.get("host", "not found"),
            "x-forwarded-for": headers.get("x-forwarded-for", "not found"),
            "x-forwarded-proto": headers.get("x-forwarded-proto", "not found"),
            "x-forwarded-access-token": headers.get("x-forwarded-access-token", "not found"),
            "user-agent": headers.get("user-agent", "not found")
        }
    }

@app.get("/debug-mcp")
async def debug_mcp():
    """Debug MCP server info"""
    return {
        "message": "MCP server info",
        "server_name": "unity-catalog-mcp",
        "version": "7.5",
        "approach": "sql_only",
        "tools_count": 6,
        "endpoint": "/mcp",
        "ready": True
    }

# =============================================
# MCP ENDPOINT - DIRECT IMPLEMENTATION
# =============================================

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """MCP endpoint using official SDK"""
    try:
        # Get the request body
        body = await request.body()
        
        # Parse JSON-RPC request
        try:
            rpc_request = json.loads(body.decode('utf-8'))
        except json.JSONDecodeError:
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                status_code=400
            )
        
        # Handle different MCP methods
        method = rpc_request.get("method")
        request_id = rpc_request.get("id")
        params = rpc_request.get("params", {})
        
        if method == "initialize":
            # Initialize response
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "unity-catalog-mcp",
                        "version": "7.5"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                },
                "id": request_id
            }
            return JSONResponse(response)
        
        elif method == "tools/list":
            # List tools
            tools = await list_tools()
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": tool.inputSchema
                        }
                        for tool in tools
                    ]
                },
                "id": request_id
            }
            return JSONResponse(response)
        
        elif method == "tools/call":
            # Call tool
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            
            result = await call_tool(tool_name, tool_args)
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "content": [
                        {
                            "type": content.type,
                            "text": content.text
                        }
                        for content in result.content
                    ]
                },
                "id": request_id
            }
            return JSONResponse(response)
        
        else:
            # Unknown method
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": request_id
                },
                status_code=400
            )
    
    except Exception as e:
        print(f"❌ MCP endpoint error: {e}")
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
                "id": rpc_request.get("id") if 'rpc_request' in locals() else None
            },
            status_code=500
        )

@app.get("/mcp")
async def mcp_get():
    """Handle GET requests to MCP endpoint"""
    return JSONResponse(
        {
            "message": "MCP endpoint",
            "method": "POST required",
            "server": "unity-catalog-mcp",
            "version": "7.5",
            "approach": "sql_only"
        }
    )

# =============================================
# STARTUP
# =============================================

print("✅ Beautiful dashboard updated to v7.5 SQL-Only!")
print("✅ Token management with live countdown timer!")
print("✅ One-click copy for token and Claude Desktop config!")
print("✅ MCP endpoint configured at /mcp")
print("✅ All tools now use SQL instead of SDK - authentication should work!")
print("🚀 Server ready to handle MCP requests!")
print("🎯 Dashboard URL: https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/")
print("🔗 Test endpoint: POST /mcp")