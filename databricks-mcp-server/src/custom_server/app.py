import time
print("🚀 Unity Catalog MCP Server - VERSION 7.4 FINAL")
print("✅ Fixed size_bytes attribute error!")
print(f"🕒 Server starting at {time.strftime('%Y-%m-%d %H:%M:%S')}")
print("📍 File path: src/custom_server/app.py")

import asyncio
import json
import os
from typing import Any, Dict, List
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
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
    """Handle tool calls"""
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
                # Use the correct SQL execution method
                result = client.statement_execution.execute_statement(
                    statement=query,
                    warehouse_id=DATABRICKS_WAREHOUSE_ID,
                    wait_timeout="30s"
                )
                
                # Get results
                if result.result and result.result.data_array:
                    results = result.result.data_array
                    return CallToolResult(
                        content=[TextContent(type="text", text=f"✅ Query executed successfully. Results: {json.dumps(results, indent=2)}")]
                    )
                else:
                    return CallToolResult(
                        content=[TextContent(type="text", text=f"✅ Query executed successfully. No data returned.")]
                    )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ SQL execution failed: {str(e)}")]
                )
        
        elif name == "list_catalogs":
            try:
                catalogs = list(client.catalogs.list())
                catalog_names = [catalog.name for catalog in catalogs]
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
                schemas = list(client.schemas.list(catalog_name=catalog_name))
                schema_names = [schema.name for schema in schemas]
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
                tables = list(client.tables.list(catalog_name=catalog_name, schema_name=schema_name))
                table_names = [table.name for table in tables]
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
                table = client.tables.get(full_name=f"{catalog_name}.{schema_name}.{table_name}")
                
                # Handle JSON serialization properly with safe attribute access
                def serialize_column(col):
                    """Serialize column info to JSON-safe format"""
                    return {
                        "name": col.name,
                        "type": str(col.type_name) if col.type_name else None,
                        "type_text": safe_get_attribute(col, 'type_text'),
                        "nullable": safe_get_attribute(col, 'nullable'),
                        "comment": safe_get_attribute(col, 'comment'),
                        "type_precision": safe_get_attribute(col, 'type_precision'),
                        "type_scale": safe_get_attribute(col, 'type_scale')
                    }
                
                table_info = {
                    "name": table.name,
                    "catalog": table.catalog_name,
                    "schema": table.schema_name,
                    "table_type": table.table_type.value if table.table_type else None,
                    "data_source_format": table.data_source_format.value if table.data_source_format else None,
                    "columns": [serialize_column(col) for col in (table.columns or [])],
                    "comment": safe_get_attribute(table, 'comment'),
                    "owner": safe_get_attribute(table, 'owner'),
                    "storage_location": safe_get_attribute(table, 'storage_location'),
                    "created_at": safe_datetime_format(safe_get_attribute(table, 'created_at')),
                    "updated_at": safe_datetime_format(safe_get_attribute(table, 'updated_at')),
                    "table_id": safe_get_attribute(table, 'table_id'),
                    "size_bytes": safe_get_attribute(table, 'size_bytes')  # FIXED: Safe attribute access
                }
                
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Table details: {json.dumps(table_info, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"❌ Error describing table: {str(e)}")]
                )
        
        elif name == "search_tables":
            catalog_name = arguments.get("catalog_name", "")
            query = arguments.get("query", "")
            
            if not catalog_name or not query:
                return CallToolResult(
                    content=[TextContent(type="text", text="❌ Error: catalog_name and query are required")]
                )
            
            try:
                schemas = list(client.schemas.list(catalog_name=catalog_name))
                matching_tables = []
                
                for schema in schemas:
                    try:
                        tables = list(client.tables.list(catalog_name=catalog_name, schema_name=schema.name))
                        for table in tables:
                            if query.lower() in table.name.lower():
                                matching_tables.append({
                                    "full_name": f"{catalog_name}.{schema.name}.{table.name}",
                                    "name": table.name,
                                    "schema": schema.name,
                                    "table_type": table.table_type.value if table.table_type else None
                                })
                    except Exception:
                        continue
                
                return CallToolResult(
                    content=[TextContent(type="text", text=f"✅ Found {len(matching_tables)} tables matching '{query}': {json.dumps(matching_tables, indent=2)}")]
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
    description="MCP server for Unity Catalog integration using official SDK",
    version="7.4",
    redirect_slashes=False
)

# Add proxy headers middleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["*"])

print("✅ FastAPI app created!")

# =============================================
# REGULAR ENDPOINTS
# =============================================

@app.get("/")
async def home():
    """Home page"""
    return {
        "message": "Unity Catalog MCP Server", 
        "version": "7.4", 
        "status": "running",
        "approach": "official_mcp_sdk"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "Unity Catalog MCP Server",
        "mcp_sdk": "official",
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
        "approach": "official_mcp_sdk",
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
                        "version": "7.4"
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
            "version": "7.4",
            "approach": "official_mcp_sdk"
        }
    )

# =============================================
# STARTUP
# =============================================

print("✅ MCP endpoint configured at /mcp")
print("✅ Fixed size_bytes attribute error - all tools should work now!")
print("🚀 Server ready to handle MCP requests!")
print("🎯 Test endpoint: POST /mcp")