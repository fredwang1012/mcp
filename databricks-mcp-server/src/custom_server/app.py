import time
print("🚀 Unity Catalog MCP Server - VERSION 7.7 SQL+OBO")
print("✅ All tools now use SQL instead of SDK calls!")
print("✅ On-Behalf-Of (OBO) authentication enabled!")
print("✅ Operations execute with user permissions!")
print(f"🕒 Server starting at {time.strftime('%Y-%m-%d %H:%M:%S')}")
print("📍 File path: src/custom_server/app.py")

import asyncio
import json
import os
import secrets
import urllib.parse
import hashlib
import base64
import httpx
from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime, timedelta, timezone
import pytz

import jwt
from fastapi import FastAPI, Request, HTTPException, Response, Form, Query
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
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
# OAUTH 2.1 CONFIGURATION
# =============================================

OAUTH_CLIENT_ID = os.environ.get('ENTRA_CLIENT_ID', 'your-client-id')
OAUTH_CLIENT_SECRET = os.environ.get('ENTRA_CLIENT_SECRET', 'your-client-secret')
OAUTH_TENANT_ID = os.environ.get('ENTRA_TENANT_ID', 'your-tenant-id')
OAUTH_REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI', 'https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/callback')

# OAuth endpoints for Microsoft Entra ID
ENTRA_AUTHORITY = f"https://login.microsoftonline.com/{OAUTH_TENANT_ID}"
ENTRA_AUTHORIZE_URL = f"{ENTRA_AUTHORITY}/oauth2/v2.0/authorize"
ENTRA_TOKEN_URL = f"{ENTRA_AUTHORITY}/oauth2/v2.0/token"

# OAuth session storage (in production, use Redis or database)
oauth_sessions = {}

print(f"🔧 OAuth Client ID: {OAUTH_CLIENT_ID}")
print(f"🔧 OAuth Tenant ID: {OAUTH_TENANT_ID}")
print(f"🔧 OAuth Redirect URI: {OAUTH_REDIRECT_URI}")

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
        print(f"🔍 Checking headers for token...")
        
        # Try Authorization header first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            print(f"Found token in Authorization header: {token[:50]}...")
            self.set_token(token)
            return True
            
        # Try x-forwarded-access-token header
        forwarded_token = request.headers.get("x-forwarded-access-token", "")
        if forwarded_token and forwarded_token != "not found":
            print(f"Found token in X-Forwarded-Access-Token header: {forwarded_token[:50]}...")
            self.set_token(forwarded_token)
            return True
        
        print(f"❌ No token found in headers")
        print(f"   Authorization: {auth_header[:50] if auth_header else 'None'}")
        print(f"   X-Forwarded-Access-Token: {forwarded_token[:50] if forwarded_token else 'None'}")
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
            print(f"Error decoding token: {e}")
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
                    "command": "powershell",
                    "args": [
                        "-ExecutionPolicy", "Bypass",
                        "-File", "C:\\\\Users\\\\YourName\\\\Downloads\\\\databricks_mcp_client.ps1"
                    ],
                    "env": {
                        "BEARER_TOKEN": self.current_token
                    }
                }
            }
        }

# Create global token manager instance
token_manager = TokenManager()

# =============================================
# MCP SESSION MANAGEMENT FOR STREAMABLE HTTP
# =============================================

import uuid
from typing import Dict, Any
from datetime import datetime

# Session storage for MCP connections
mcp_sessions: Dict[str, Any] = {}

class MCPSessionManager:
    """Manages MCP sessions for Streamable HTTP protocol"""
    
    @staticmethod
    def create_session() -> str:
        session_id = str(uuid.uuid4())
        mcp_sessions[session_id] = {
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'transport_state': {},
            'client_info': {}
        }
        print(f"📝 Created MCP session: {session_id}")
        return session_id
    
    @staticmethod
    def get_session(session_id: str) -> Dict[str, Any]:
        session = mcp_sessions.get(session_id)
        if session:
            session['last_activity'] = datetime.utcnow()
        return session
    
    @staticmethod
    def cleanup_session(session_id: str):
        if session_id in mcp_sessions:
            del mcp_sessions[session_id]
            print(f"🗑️ Cleaned up MCP session: {session_id}")
    
    @staticmethod
    def cleanup_expired_sessions(max_age_hours: int = 24):
        """Clean up sessions older than max_age_hours"""
        now = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in mcp_sessions.items():
            age = now - session_data['created_at']
            if age.total_seconds() > (max_age_hours * 3600):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            MCPSessionManager.cleanup_session(session_id)
        
        if expired_sessions:
            print(f"🧹 Cleaned up {len(expired_sessions)} expired sessions")

# Create global session manager instance
session_manager = MCPSessionManager()

# =============================================
# DATABRICKS CLIENT
# =============================================

def get_databricks_client(token=None):
    """Get authenticated Databricks client with OBO support
    
    Uses On-Behalf-Of authentication when token is provided, allowing
    operations to execute with the user's permissions rather than
    the app's service principal permissions.
    """
    try:
        if token:
            # Use OBO authentication with user's OAuth token
            # CRITICAL: auth_type="pat" is required for OBO per Databricks documentation
            client = WorkspaceClient(
                host=DATABRICKS_HOST,
                token=token,
                auth_type="pat"  # Required for OBO authentication
            )
        else:
            # Fall back to default authentication
            client = WorkspaceClient()
        return client
    except Exception as e:
        print(f"❌ Error initializing Databricks client: {e}")
        return None

def validate_obo_user(client):
    """Validate OBO authentication by getting current user info"""
    try:
        current_user = client.current_user.me()
        print(f"✅ OBO authenticated as: {current_user.user_name} ({current_user.display_name})")
        return True, current_user.user_name
    except Exception as e:
        print(f"⚠️ Could not validate OBO user: {e}")
        return False, None

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

@server.list_resources()
async def list_resources():
    """List available resources (empty for now)"""
    return []

@server.list_prompts()
async def list_prompts():
    """List available prompts (empty for now)"""
    return []

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
    """Handle tool calls using SQL for everything"""
    try:
        # Debug logging
        print(f"🔍 call_tool invoked: {name}")
        print(f"🔍 Token available: {token_manager.current_token is not None}")
        if token_manager.current_token:
            print(f"🔍 Token length: {len(token_manager.current_token)}")
            print(f"🔍 Token prefix: {token_manager.current_token[:50]}...")
        
        # Get client with current token from token_manager
        client = get_databricks_client(token=token_manager.current_token)
        if not client:
            print(f"❌ Failed to create client. Token: {token_manager.current_token is not None}")
            return CallToolResult(
                content=[TextContent(type="text", text="Error: Unable to connect to Databricks")]
            )
        
        # Validate OBO authentication (optional - helps verify it's working)
        if token_manager.current_token:
            is_obo, username = validate_obo_user(client)
            if is_obo:
                print(f"🎯 Executing '{name}' as user: {username}")
            else:
                print(f"⚠️ OBO validation failed, continuing with service principal")
        else:
            print(f"📝 No user token - using service principal authentication")
        
        if name == "query_sql":
            query = arguments.get("query", "")
            if not query:
                return CallToolResult(
                    content=[TextContent(type="text", text="Error: query is required")]
                )
            
            try:
                results = execute_sql_query(client, query)
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Query executed successfully. Results: {json.dumps(results, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"SQL execution failed: {str(e)}")]
                )
        
        elif name == "list_catalogs":
            try:
                # Use SQL instead of SDK
                results = execute_sql_query(client, "SHOW CATALOGS")
                catalog_names = [row[0] for row in results]  # First column contains catalog names
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Available catalogs: {json.dumps(catalog_names, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error listing catalogs: {str(e)}")]
                )
        
        elif name == "list_schemas":
            catalog_name = arguments.get("catalog_name", "")
            if not catalog_name:
                return CallToolResult(
                    content=[TextContent(type="text", text="Error: catalog_name is required")]
                )
            
            try:
                # Use SQL instead of SDK
                query = f"SHOW SCHEMAS IN {catalog_name}"
                results = execute_sql_query(client, query)
                schema_names = [row[0] for row in results]  # First column contains schema names
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Schemas in catalog '{catalog_name}': {json.dumps(schema_names, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error listing schemas: {str(e)}")]
                )
        
        elif name == "list_tables":
            catalog_name = arguments.get("catalog_name", "")
            schema_name = arguments.get("schema_name", "")
            
            if not catalog_name or not schema_name:
                return CallToolResult(
                    content=[TextContent(type="text", text="Error: catalog_name and schema_name are required")]
                )
            
            try:
                # Use SQL instead of SDK
                query = f"SHOW TABLES IN {catalog_name}.{schema_name}"
                results = execute_sql_query(client, query)
                # SHOW TABLES returns: [schema_name, table_name, is_temporary]
                table_names = [row[1] if len(row) > 1 else row[0] for row in results]  # Second column contains table names
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Tables in schema '{catalog_name}.{schema_name}': {json.dumps(table_names, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error listing tables: {str(e)}")]
                )
        
        elif name == "describe_table":
            catalog_name = arguments.get("catalog_name", "")
            schema_name = arguments.get("schema_name", "")
            table_name = arguments.get("table_name", "")
            
            if not catalog_name or not schema_name or not table_name:
                return CallToolResult(
                    content=[TextContent(type="text", text="Error: catalog_name, schema_name, and table_name are required")]
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
                    content=[TextContent(type="text", text=f"Table details: {json.dumps(table_info, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error describing table: {str(e)}")]
                )
        
        elif name == "search_tables":
            catalog_name = arguments.get("catalog_name", "")
            search_query = arguments.get("query", "")
            
            if not catalog_name or not search_query:
                return CallToolResult(
                    content=[TextContent(type="text", text="Error: catalog_name and query are required")]
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
                            table_name = table_row[1] if len(table_row) > 1 else table_row[0]
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
                    content=[TextContent(type="text", text=f"Found {len(matching_tables)} tables matching '{search_query}': {json.dumps(matching_tables, indent=2)}")]
                )
            except Exception as e:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error searching tables: {str(e)}")]
                )
        
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")]
            )
    
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error executing tool {name}: {str(e)}")]
        )

print("✅ MCP tools registered successfully!")

# =============================================
# FASTAPI SETUP
# =============================================

app = FastAPI(
    title="Unity Catalog MCP Server",
    description="MCP server for Unity Catalog integration using SQL only",
    version="7.7",
    redirect_slashes=False
)

# Add proxy headers middleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=["*"])

# Add enhanced CORS middleware for Claude.ai integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://claude.ai",
        "https://claude.com", 
        "https://claude.anthropic.com",
        "*"  # Allow all for development - restrict in production
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=[
        "Accept",
        "Authorization", 
        "Content-Type",
        "Mcp-Session-Id",
        "MCP-Protocol-Version",
        "X-Forwarded-Access-Token",
        "Origin",
        "Referer"
    ],
    expose_headers=[
        "Mcp-Session-Id", 
        "WWW-Authenticate",
        "Content-Type",
        "Access-Control-Allow-Origin"
    ]
)

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
        
        .btn-primary {{
            background: #007bff;
            padding: 5px 15px;
            font-size: 0.9rem;
        }}
        
        .btn-primary:hover {{
            background: #0056b3;
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
            <h1>🚀 Unity Catalog MCP Dashboard <span class="version-badge">v7.7 SQL+OBO</span></h1>
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
                        <li>Download the PowerShell client: <button class="btn btn-primary" style="margin-left: 10px;" onclick="window.location.href='/download/powershell-client'">💾 Download PowerShell Client</button></li>
                        <li>Save it to Downloads folder (e.g., C:\\Users\\YourName\\Downloads\\)</li>
                        <li>Copy the configuration to Claude Desktop settings.json</li>
                        <li>Restart Claude Desktop</li>
                    </ol>
                    
                    <!-- Alternative Node.js Setup:
                    If you prefer Node.js, use this configuration instead:
                    {{
                      "mcpServers": {{
                        "unity-catalog": {{
                          "command": "node",
                          "args": ["C:\\Users\\YourName\\mcp\\databricks_mcp_client.js"],
                          "env": {{"BEARER_TOKEN": "your-token-here"}}
                        }}
                      }}
                    }}
                    -->
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
                    <span>🔐</span> OAuth 2.1 Authentication (NEW!)
                </div>
                
                <p style="margin-bottom: 15px; color: #28a745; font-weight: 600;">
                    ✨ No more manual token management! Use OAuth with Microsoft Entra ID.
                </p>
                
                <div class="instructions">
                    <h3>🎯 For Claude Code Users:</h3>
                    <ol>
                        <li>Claude Code will automatically discover OAuth endpoints</li>
                        <li>Your browser will open to login with Microsoft</li>
                        <li>Tokens will be managed automatically</li>
                        <li>OBO (On-Behalf-Of) permissions still work!</li>
                    </ol>
                    
                    <h3>🔗 OAuth Endpoints:</h3>
                    <ul>
                        <li><strong>Discovery:</strong> <code>/.well-known/oauth-authorization-server</code></li>
                        <li><strong>Authorize:</strong> <code>/authorize</code></li>
                        <li><strong>Token:</strong> <code>/token</code></li>
                    </ul>
                    
                    <h3>⚙️ Environment Variables (for administrators):</h3>
                    <div class="code-block" style="font-size: 0.8rem;">
ENTRA_CLIENT_ID=your-app-registration-client-id
ENTRA_CLIENT_SECRET=your-app-registration-secret  
ENTRA_TENANT_ID=your-azure-tenant-id
OAUTH_REDIRECT_URI=https://your-app-url/callback</div>
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
                    <a href="/.well-known/oauth-authorization-server" target="_blank" class="btn">🔐 OAuth Discovery</a>
                    <button class="btn" onclick="testConnection()">🧪 Test Connection</button>
                </div>
                
                <div class="instructions">
                    <h3>🚀 Available Tools (SQL+OBO):</h3>
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
            "version": "7.7",
            "name": "unity-catalog-mcp",
            "tools_count": 6,
            "endpoint": "/mcp",
            "approach": "sql_with_obo"
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
        "version": "7.7",
        "approach": "sql_with_obo",
        "endpoint": "/mcp"
    }

# @app.get("/download/client")
# async def download_client():
#     """Download the MCP client JavaScript file"""
#     client_js_content = '''#!/usr/bin/env node
# 
# const readline = require('readline');
# const https = require('https');
# 
# // Configuration
# const SERVER_URL = 'https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/mcp';
# const TOKEN = process.env.BEARER_TOKEN;
# 
# if (!TOKEN) {
#   console.error('Error: BEARER_TOKEN environment variable is required');
#   process.exit(1);
# }
# 
# // Create interfaces for stdio
# const rl = readline.createInterface({
#   input: process.stdin,
#   output: process.stdout,
#   terminal: false
# });
# 
# // Handle incoming requests from Claude
# rl.on('line', async (line) => {
#   try {
#     const request = JSON.parse(line);
#     
#     // Make HTTPS request to Databricks Apps
#     const response = await makeHttpsRequest(request);
#     
#     // Send response back to Claude
#     console.log(JSON.stringify(response));
#   } catch (error) {
#     console.error(JSON.stringify({
#       jsonrpc: "2.0",
#       error: {
#         code: -32603,
#         message: error.message
#       },
#       id: null
#     }));
#   }
# });
# 
# function makeHttpsRequest(requestBody) {
#   return new Promise((resolve, reject) => {
#     const postData = JSON.stringify(requestBody);
#     
#     const url = new URL(SERVER_URL);
#     const options = {
#       hostname: url.hostname,
#       port: 443,
#       path: url.pathname,
#       method: 'POST',
#       headers: {
#         'Authorization': `Bearer ${TOKEN}`,
#         'Content-Type': 'application/json',
#         'Content-Length': Buffer.byteLength(postData)
#       }
#     };
# 
#     const req = https.request(options, (res) => {
#       let data = '';
#       
#       res.on('data', (chunk) => {
#         data += chunk;
#       });
#       
#       res.on('end', () => {
#         if (!data || data.trim() === '') {
#           reject(new Error('Empty response from server'));
#           return;
#         }
#         
#         try {
#           const response = JSON.parse(data);
#           resolve(response);
#         } catch (e) {
#           reject(new Error(`Invalid JSON response: ${data}`));
#         }
#       });
#     });
# 
#     req.on('error', (err) => {
#       reject(err);
#     });
# 
#     req.write(postData);
#     req.end();
#   });
# }
# 
# // Handle process termination
# process.on('SIGINT', () => {
#   process.exit(0);
# });
# 
# process.on('SIGTERM', () => {
#   process.exit(0);
# });
# '''
#     
#     from fastapi.responses import Response
#     return Response(
#         content=client_js_content,
#         media_type="application/javascript",
#         headers={
#             "Content-Disposition": "attachment; filename=databricks_mcp_client.js"
#         }
#     )

@app.get("/download/powershell-client")
async def download_powershell_client():
    """Download the MCP client PowerShell file"""
    client_ps_content = '''# Databricks MCP Client - PowerShell Version
# Exact equivalent of the Node.js version, no dependencies required

$SERVER_URL = 'https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/mcp'
$TOKEN = $env:BEARER_TOKEN

# Enable TLS 1.2 for HTTPS requests
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Invoke-MakeRequest {
    param([object]$RequestBody)
    
    try {
        $postData = $RequestBody | ConvertTo-Json -Depth 10 -Compress
        $postDataBytes = [System.Text.Encoding]::UTF8.GetBytes($postData)
        
        $headers = @{
            'Authorization' = "Bearer $TOKEN"
            'Content-Type' = 'application/json'
            'Content-Length' = $postDataBytes.Length
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0'
        }
        
        $response = Invoke-RestMethod -Uri $SERVER_URL -Method POST -Headers $headers -Body $postData -ContentType 'application/json'
        return $response
    }
    catch {
        $statusCode = $null
        $responseBody = ''
        
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $responseBody = $reader.ReadToEnd()
                $reader.Close()
                $stream.Close()
            }
            catch {
                $responseBody = $_.Exception.Message
            }
        }
        
        if ($statusCode -ne $null) {
            throw "HTTP $statusCode`: $responseBody"
        } else {
            throw $_.Exception.Message
        }
    }
}

# Main processing loop - read from stdin line by line
try {
    while ($true) {
        $inputLine = [Console]::ReadLine()
        
        # Exit if null (EOF)
        if ($inputLine -eq $null) {
            break
        }
        
        $request = $null
        $requestId = $null
        
        try {
            # Parse the JSON-RPC request
            $request = $inputLine.Trim() | ConvertFrom-Json
            $requestId = $request.id
            
            # Validate basic JSON-RPC structure
            if (-not $request.jsonrpc -or $request.jsonrpc -ne "2.0") {
                throw "Invalid JSON-RPC version"
            }
            
            # Handle notifications (no id field, no response required)
            if ($requestId -eq $null -or $requestId.GetType().Name -eq 'DBNull') {
                if ($request.method -eq 'notifications/initialized') {
                    # Notifications don't require a response
                    continue
                }
                # Other methods require an ID
                throw "Missing request ID"
            }
            
            if ($request.method -eq 'initialize') {
                $initResponse = @{
                    jsonrpc = "2.0"
                    result = @{
                        protocolVersion = "2024-11-05"
                        serverInfo = @{
                            name = "databricks-mcp-client"
                            version = "1.0.0"
                        }
                        capabilities = @{
                            tools = @{}
                        }
                    }
                    id = $requestId
                }
                $json = $initResponse | ConvertTo-Json -Depth 10 -Compress
                Write-Output $json
                continue
            }
            
            # Forward request to server
            $response = Invoke-MakeRequest -RequestBody $request
            
            # Build a clean JSON-RPC response
            $finalResponse = @{
                jsonrpc = "2.0"
                id = $requestId
            }
            
            # Copy either result or error, but not both
            if ($response.PSObject.Properties.Name -contains 'result') {
                $finalResponse.result = $response.result
            } elseif ($response.PSObject.Properties.Name -contains 'error') {
                $finalResponse.error = $response.error
            } else {
                # If neither result nor error, treat entire response as result
                $finalResponse.result = $response
            }
            
            $json = $finalResponse | ConvertTo-Json -Depth 10 -Compress
            Write-Output $json
            
        }
        catch {
            # Create a proper JSON-RPC error response
            $errorResponse = @{
                jsonrpc = "2.0"
                error = @{
                    code = -32603
                    message = $_.Exception.Message
                }
                id = $requestId
            }
            
            $json = $errorResponse | ConvertTo-Json -Depth 10 -Compress
            Write-Output $json
        }
    }
}
catch {
    # Handle any unhandled exceptions
    $errorResponse = @{
        jsonrpc = "2.0"
        error = @{
            code = -32603
            message = $_.Exception.Message
        }
        id = $null
    }
    
    $json = $errorResponse | ConvertTo-Json -Depth 10 -Compress
    Write-Output $json
}
'''
    
    from fastapi.responses import Response
    return Response(
        content=client_ps_content,
        media_type="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=databricks_mcp_client.ps1"
        }
    )

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
        "version": "7.7",
        "approach": "sql_with_obo",
        "tools_count": 6,
        "endpoint": "/mcp",
        "ready": True
    }

# =============================================
# MCP ENDPOINT - DIRECT IMPLEMENTATION
# =============================================

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """Enhanced MCP endpoint with Streamable HTTP + your perfect OBO authentication"""
    try:
        # 🎯 Keep your existing perfect token management
        token_manager.update_token_from_request(request)
        
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
        
        # 🆕 Add session management for Streamable HTTP
        session_id = request.headers.get('mcp-session-id')
        
        # Handle session creation for initialize requests or missing session
        if method == "initialize" or not session_id:
            # Create new session
            session_id = session_manager.create_session()
            print(f"🚀 Initialize request - created session: {session_id}")
            
            response_data = {
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "unity-catalog-mcp",
                        "version": "7.7"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                },
                "id": request_id
            }
            
            response = JSONResponse(response_data)
            response.headers['Mcp-Session-Id'] = session_id
            response.headers['Access-Control-Expose-Headers'] = 'Mcp-Session-Id'
            return response
        
        # Validate existing session for non-initialize requests
        session = session_manager.get_session(session_id)
        if not session:
            print(f"❌ Session not found: {session_id}")
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32001, "message": "Session not found - please reinitialize"},
                    "id": request_id
                },
                status_code=404,
                headers={'Mcp-Session-Id': session_id}
            )
        
        print(f"✅ Using existing session: {session_id}")
        
        # Handle notifications (no id field - just acknowledge and return)
        if request_id is None:
            print(f"📬 Received notification: {method}")
            # Notifications don't require a response - return 202 Accepted per spec
            response = Response(status_code=202)
            response.headers['Mcp-Session-Id'] = session_id
            return response
        
        # 🎯 Keep all your existing MCP method handling logic
        if method == "tools/list":
            # List tools - using your existing perfect implementation
            tools = await list_tools()
            response_data = {
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
            
        elif method == "tools/call":
            # Call tool - using your existing perfect implementation with OBO
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            
            result = await call_tool(tool_name, tool_args)
            response_data = {
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
            
        elif method == "resources/list":
            # List resources (empty for now)
            response_data = {
                "jsonrpc": "2.0",
                "result": {
                    "resources": []
                },
                "id": request_id
            }
            
        elif method == "prompts/list":
            # List prompts (empty for now) 
            response_data = {
                "jsonrpc": "2.0",
                "result": {
                    "prompts": []
                },
                "id": request_id
            }
            
        else:
            # Unknown method
            response_data = {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method}"},
                "id": request_id
            }
        
        # Return response with session header
        response = JSONResponse(response_data)
        response.headers['Mcp-Session-Id'] = session_id
        response.headers['Access-Control-Expose-Headers'] = 'Mcp-Session-Id'
        return response
        
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
async def mcp_sse_endpoint(request: Request):
    """MCP SSE stream endpoint for real-time communication with Claude.ai"""
    try:
        # Check if client wants SSE (required for Streamable HTTP spec)
        accept = request.headers.get("accept", "")
        if "text/event-stream" not in accept:
            return JSONResponse(
                status_code=405,
                content={
                    "error": "Method not allowed - SSE stream required",
                    "message": "Use POST for JSON-RPC requests, GET with Accept: text/event-stream for SSE",
                    "server": "unity-catalog-mcp",
                    "version": "7.7"
                }
            )
        
        # 🎯 Keep your existing perfect token management
        token_manager.update_token_from_request(request)
        print("🔌 SSE stream requested by client")
        
        # Create session for SSE connection
        session_id = session_manager.create_session()
        print(f"📡 Created SSE session: {session_id}")
        
        async def event_generator():
            try:
                # Send initial session info to client
                initial_message = {
                    "type": "session_created",
                    "sessionId": session_id,
                    "server": "unity-catalog-mcp",
                    "version": "7.7",
                    "timestamp": datetime.utcnow().isoformat()
                }
                yield f"data: {json.dumps(initial_message)}\n\n"
                
                # Keep connection alive with periodic heartbeat
                heartbeat_count = 0
                while True:
                    await asyncio.sleep(30)  # Heartbeat every 30 seconds
                    heartbeat_count += 1
                    
                    heartbeat_message = {
                        "type": "heartbeat",
                        "sessionId": session_id,
                        "count": heartbeat_count,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    yield f"data: {json.dumps(heartbeat_message)}\n\n"
                    
            except asyncio.CancelledError:
                # Client disconnected - clean up session
                session_manager.cleanup_session(session_id)
                print(f"🔌 SSE connection closed for session: {session_id}")
                
        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Accept, Authorization, Content-Type, Mcp-Session-Id",
                "Access-Control-Expose-Headers": "Mcp-Session-Id",
                "Mcp-Session-Id": session_id
            }
        )
        
    except Exception as e:
        print(f"❌ SSE endpoint error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": f"SSE setup failed: {str(e)}"}
        )

@app.delete("/mcp")
async def mcp_cleanup(request: Request):
    """Clean up MCP session - part of Streamable HTTP spec"""
    try:
        session_id = request.headers.get('mcp-session-id')
        print(f"🗑️ Cleanup requested for session: {session_id}")
        
        if session_id and session_id in mcp_sessions:
            session_manager.cleanup_session(session_id)
            print(f"✅ Session {session_id} cleaned up successfully")
            return Response(status_code=204)  # No Content - success
        else:
            print(f"❌ Session {session_id} not found for cleanup")
            return JSONResponse(
                status_code=404,
                content={"error": "Session not found"}
            )
            
    except Exception as e:
        print(f"❌ Session cleanup error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Session cleanup failed: {str(e)}"}
        )

# =============================================
# OAUTH 2.1 ENDPOINTS
# =============================================

@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    """OAuth 2.1 Protected Resource Discovery"""
    return JSONResponse({
        "resource": "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com",
        "authorization_servers": ["https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com"],
        "scopes_supported": ["mcp:tools", "databricks:read", "databricks:write"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/docs"
    })

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server():
    """OAuth 2.1 Authorization Server Discovery"""
    return JSONResponse({
        "issuer": "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com",
        "authorization_endpoint": "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/authorize",
        "token_endpoint": "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/token",
        "scopes_supported": ["mcp:tools", "databricks:read", "databricks:write"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]
    })

@app.get("/authorize")
async def oauth_authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="mcp:tools"),
    state: Optional[str] = Query(default=None),
    code_challenge: Optional[str] = Query(default=None),
    code_challenge_method: Optional[str] = Query(default="S256")
):
    """OAuth 2.1 Authorization Endpoint - redirects to Microsoft Entra ID"""
    
    # Validate parameters
    if response_type != "code":
        raise HTTPException(400, "Only 'code' response type supported")
    
    if code_challenge_method and code_challenge_method != "S256":
        raise HTTPException(400, "Only 'S256' code challenge method supported")
    
    # Generate session state
    session_id = secrets.token_urlsafe(32)
    oauth_sessions[session_id] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "created_at": datetime.now(timezone.utc)
    }
    
    # Build Microsoft Entra ID authorization URL
    entra_params = {
        "response_type": "code",
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "scope": "https://adb-1761712055023179.19.azuredatabricks.net/.default offline_access",
        "state": session_id,
        "response_mode": "query"
    }
    
    entra_url = f"{ENTRA_AUTHORIZE_URL}?{urllib.parse.urlencode(entra_params)}"
    return RedirectResponse(url=entra_url)

@app.get("/callback")
async def oauth_callback(
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    error_description: Optional[str] = Query(default=None)
):
    """OAuth callback from Microsoft Entra ID"""
    
    if error:
        return HTMLResponse(f"""
            <html><body>
                <h1>OAuth Error</h1>
                <p>Error: {error}</p>
                <p>Description: {error_description or 'N/A'}</p>
            </body></html>
        """, status_code=400)
    
    if not code or not state:
        return HTMLResponse("<html><body><h1>Missing code or state parameter</h1></body></html>", status_code=400)
    
    # Retrieve session
    session = oauth_sessions.get(state)
    if not session:
        return HTMLResponse("<html><body><h1>Invalid or expired session</h1></body></html>", status_code=400)
    
    try:
        # Exchange code for tokens with Microsoft Entra ID
        async with httpx.AsyncClient() as client:
            token_data = {
                "grant_type": "authorization_code",
                "client_id": OAUTH_CLIENT_ID,
                "client_secret": OAUTH_CLIENT_SECRET,
                "code": code,
                "redirect_uri": OAUTH_REDIRECT_URI,
                "scope": "https://adb-1761712055023179.19.azuredatabricks.net/.default offline_access"
            }
            
            response = await client.post(ENTRA_TOKEN_URL, data=token_data)
            
            if response.status_code != 200:
                return HTMLResponse(f"""
                    <html><body>
                        <h1>Token Exchange Failed</h1>
                        <p>Status: {response.status_code}</p>
                        <p>Response: {response.text}</p>
                    </body></html>
                """, status_code=400)
            
            tokens = response.json()
            
            # Generate authorization code for the original client
            auth_code = secrets.token_urlsafe(32)
            
            # Store the Databricks token for later exchange
            oauth_sessions[auth_code] = {
                **session,
                "databricks_access_token": tokens.get("access_token"),
                "databricks_refresh_token": tokens.get("refresh_token"),
                "expires_at": datetime.now(timezone.utc) + timedelta(seconds=tokens.get("expires_in", 3600))
            }
            
            # Clean up the original session
            del oauth_sessions[state]
            
            # Redirect back to the original client with authorization code
            redirect_params = {"code": auth_code}
            if session["state"]:
                redirect_params["state"] = session["state"]
            
            redirect_url = f"{session['redirect_uri']}?{urllib.parse.urlencode(redirect_params)}"
            return RedirectResponse(url=redirect_url)
            
    except Exception as e:
        return HTMLResponse(f"""
            <html><body>
                <h1>OAuth Processing Error</h1>
                <p>Error: {str(e)}</p>
            </body></html>
        """, status_code=500)

@app.post("/exchange-token")
async def exchange_entra_token(request: Request):
    """Exchange Entra ID token for Databricks token"""
    try:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({
                "error": "invalid_request",
                "error_description": "Missing or invalid Authorization header"
            }, status_code=400)
        
        entra_token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Use Databricks token federation to exchange Entra ID token
        exchange_url = f"{DATABRICKS_HOST}/oidc/v1/token"
        
        exchange_data = {
            "subject_token": entra_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "scope": "all-apis"
        }
        
        async with httpx.AsyncClient() as client:
            exchange_response = await client.post(exchange_url, data=exchange_data)
            
            if exchange_response.status_code == 200:
                tokens = exchange_response.json()
                return JSONResponse({
                    "access_token": tokens.get("access_token"),
                    "token_type": "Bearer",
                    "expires_in": tokens.get("expires_in", 3600)
                })
            else:
                return JSONResponse({
                    "error": "token_exchange_failed",
                    "error_description": f"Databricks token exchange failed: {exchange_response.text}"
                }, status_code=400)
                
    except Exception as e:
        return JSONResponse({
            "error": "server_error", 
            "error_description": str(e)
        }, status_code=500)

@app.post("/token")
async def oauth_token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(default=None),
    redirect_uri: Optional[str] = Form(default=None),
    client_id: Optional[str] = Form(default=None),
    client_secret: Optional[str] = Form(default=None),
    code_verifier: Optional[str] = Form(default=None)
):
    """OAuth 2.1 Token Endpoint"""
    
    if grant_type != "authorization_code":
        return JSONResponse({
            "error": "unsupported_grant_type",
            "error_description": "Only authorization_code grant type is supported"
        }, status_code=400)
    
    if not code:
        return JSONResponse({
            "error": "invalid_request",
            "error_description": "Missing authorization code"
        }, status_code=400)
    
    # Retrieve session with Databricks tokens
    session = oauth_sessions.get(code)
    if not session:
        return JSONResponse({
            "error": "invalid_grant",
            "error_description": "Invalid or expired authorization code"
        }, status_code=400)
    
    # Validate client credentials
    if client_id != session.get("client_id"):
        return JSONResponse({
            "error": "invalid_client",
            "error_description": "Client ID mismatch"
        }, status_code=400)
    
    # Validate PKCE if used
    if session.get("code_challenge") and code_verifier:
        # Verify code challenge
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        expected_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
        
        if session["code_challenge"] != expected_challenge:
            return JSONResponse({
                "error": "invalid_grant",
                "error_description": "Code verifier does not match challenge"
            }, status_code=400)
    
    # Clean up the session
    databricks_token = session["databricks_access_token"]
    del oauth_sessions[code]
    
    # Return the Databricks access token as our OAuth token
    return JSONResponse({
        "access_token": databricks_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": session.get("scope", "mcp:tools")
    })

# =============================================
# STARTUP
# =============================================

print("✅ Beautiful dashboard updated to v7.7 SQL+OBO!")
print("✅ Token management with live countdown timer!")
print("✅ One-click copy for token and Claude Desktop config!")
print("✅ MCP endpoint configured at /mcp")
print("✅ All tools now use SQL instead of SDK - authentication should work!")
print("🚀 Server ready to handle MCP requests!")
print("🎯 Dashboard URL: https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/")
print("🔗 Test endpoint: POST /mcp")