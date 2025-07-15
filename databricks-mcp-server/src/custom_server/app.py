import time
print("🚀 Unity Catalog MCP Server - VERSION 7.0 OFFICIAL MCP SDK")
print("✅ Using official MCP SDK - abandoning FastMCP!")
print(f"🕒 Server starting at {time.strftime('%Y-%m-%d %H:%M:%S')}")
print("📍 File path: src/custom_server/app.py")

import asyncio
import json
import os
from typing import Any, Dict, List
from pathlib import Path

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
            with client.sql.statement_execution.create(query=query, warehouse_id=DATABRICKS_WAREHOUSE_ID) as cursor:
                result = cursor.fetchall()
            return CallToolResult(
                content=[TextContent(type="text", text=f"✅ Query executed successfully. Results: {json.dumps(result, indent=2)}")]
            )
        
        elif name == "list_catalogs":
            catalogs = list(client.catalogs.list())
            catalog_names = [catalog.name for catalog in catalogs]
            return CallToolResult(
                content=[TextContent(type="text", text=f"✅ Available catalogs: {json.dumps(catalog_names, indent=2)}")]
            )
        
        elif name == "list_schemas":
            catalog_name = arguments.get("catalog_name", "")
            schemas = list(client.schemas.list(catalog_name=catalog_name))
            schema_names = [schema.name for schema in schemas]
            return CallToolResult(
                content=[TextContent(type="text", text=f"✅ Schemas in catalog '{catalog_name}': {json.dumps(schema_names, indent=2)}")]
            )
        
        elif name == "list_tables":
            catalog_name = arguments.get("catalog_name", "")
            schema_name = arguments.get("schema_name", "")
            tables = list(client.tables.list(catalog_name=catalog_name, schema_name=schema_name))
            table_names = [table.name for table in tables]
            return CallToolResult(
                content=[TextContent(type="text", text=f"✅ Tables in schema '{catalog_name}.{schema_name}': {json.dumps(table_names, indent=2)}")]
            )
        
        elif name == "describe_table":
            catalog_name = arguments.get("catalog_name", "")
            schema_name = arguments.get("schema_name", "")
            table_name = arguments.get("table_name", "")
            table = client.tables.get(full_name=f"{catalog_name}.{schema_name}.{table_name}")
            
            table_info = {
                "name": table.name,
                "catalog": table.catalog_name,
                "schema": table.schema_name,
                "table_type": table.table_type,
                "data_source_format": table.data_source_format,
                "columns": [{"name": col.name, "type": col.type_name} for col in table.columns] if table.columns else [],
                "comment": table.comment
            }
            
            return CallToolResult(
                content=[TextContent(type="text", text=f"✅ Table details: {json.dumps(table_info, indent=2)}")]
            )
        
        elif name == "search_tables":
            catalog_name = arguments.get("catalog_name", "")
            query = arguments.get("query", "")
            
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
                                "table_type": table.table_type
                            })
                except Exception:
                    continue
            
            return CallToolResult(
                content=[TextContent(type="text", text=f"✅ Found {len(matching_tables)} tables matching '{query}': {json.dumps(matching_tables, indent=2)}")]
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
    version="7.0",
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
        "version": "7.0", 
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
                        "version": "7.0"
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
            "version": "7.0",
            "approach": "official_mcp_sdk"
        }
    )

# =============================================
# STARTUP
# =============================================

print("✅ MCP endpoint configured at /mcp")
print("✅ Using official MCP SDK - no mounting issues!")
print("🚀 Server ready to handle MCP requests!")
print("🎯 Test endpoint: POST /mcp")