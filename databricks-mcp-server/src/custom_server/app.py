from pathlib import Path
from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from databricks.sdk import WorkspaceClient
import os

STATIC_DIR = Path(__file__).parent / "static"

# Create an MCP server
mcp = FastMCP("Unity Catalog SQL MCP Server")

# Databricks configuration
DATABRICKS_HOST = os.environ.get("DATABRICKS_HOST", "https://adb-1761712055023179.19.azuredatabricks.net")
WAREHOUSE_ID = os.environ.get("DATABRICKS_WAREHOUSE_ID", "a85c850e7621e163")


def get_databricks_client(user_token: str | None = None):
    """Get Databricks workspace client using user's access token or app authentication"""
    try:
        if user_token:
            # Temporarily remove OAuth env vars to avoid conflict with user token
            old_client_id = os.environ.pop('DATABRICKS_CLIENT_ID', None)
            old_client_secret = os.environ.pop('DATABRICKS_CLIENT_SECRET', None)
            
            try:
                client = WorkspaceClient(
                    host=DATABRICKS_HOST,
                    token=user_token
                )
                print(f"Using user's access token for authentication")
            finally:
                # Restore OAuth env vars for other uses
                if old_client_id:
                    os.environ['DATABRICKS_CLIENT_ID'] = old_client_id
                if old_client_secret:
                    os.environ['DATABRICKS_CLIENT_SECRET'] = old_client_secret
        else:
            # Fallback to service principal authentication
            client = WorkspaceClient()
            print(f"Using service principal authentication")
        return client
    except Exception as e:
        print(f"Error creating Databricks client: {e}")
        return None


# Add a SQL query tool
@mcp.tool()
def execute_sql_query(sql_query: str, limit: int = 100) -> str:
    """Execute a SQL query against Unity Catalog"""
    try:
        client = get_databricks_client()
        if not client:
            return "Error: Failed to create Databricks client"
        
        # Execute the statement
        response = client.statement_execution.execute_statement(
            statement=sql_query,
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        # Get the result
        if hasattr(response, 'statement_id') and response.statement_id:
            result = client.statement_execution.get_statement(statement_id=response.statement_id)
            
            if hasattr(result, 'result') and result.result:
                if hasattr(result.result, 'data_array'):
                    rows = result.result.data_array[:limit] if result.result.data_array else []
                    return f"Query succeeded!\nRows: {rows}"
                    
        return "No results returned"
            
    except Exception as e:
        return f"Error executing query: {str(e)}"


# Add a Unity Catalog tables resource
@mcp.resource("unity-catalog://tables")
def get_available_tables() -> str:
    """Get available Unity Catalog tables"""
    try:
        client = get_databricks_client()
        if not client:
            return "Error: Failed to create Databricks client"
        
        # List catalogs
        catalogs = list(client.catalogs.list())
        
        result = "Available Unity Catalog Tables:\n"
        result += "=" * 40 + "\n\n"
        
        for catalog in catalogs[:5]:  # Limit to first 5 catalogs
            result += f"📁 Catalog: {catalog.name}\n"
            
            try:
                # List schemas in catalog
                if catalog.name:
                    schemas = list(client.schemas.list(catalog_name=catalog.name))
                    for schema in schemas[:3]:  # Limit to first 3 schemas per catalog
                        result += f"  📂 Schema: {schema.name}\n"
                        
                        try:
                            # List tables in schema
                            if schema.name:
                                tables = list(client.tables.list(
                                    catalog_name=catalog.name,
                                    schema_name=schema.name
                                ))
                                for table in tables[:5]:  # Limit to first 5 tables per schema
                                    table_type = getattr(table, 'table_type', 'TABLE')
                                    result += f"    📄 {table.name} ({table_type})\n"
                        except Exception as e:
                            result += f"    ❌ Error listing tables: {str(e)}\n"
                        
            except Exception as e:
                result += f"  ❌ Error listing schemas: {str(e)}\n"
            
            result += "\n"
        
        return result
        
    except Exception as e:
        return f"Error accessing Unity Catalog: {str(e)}"


# Create the streamable HTTP app
mcp_app = mcp.streamable_http_app()

# Create FastAPI app
app = FastAPI(
    lifespan=lambda _: mcp.session_manager.run(),
)


@app.get("/", include_in_schema=False)
async def serve_index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return JSONResponse({"status": "healthy", "service": "Unity Catalog MCP Server"})


# Add redirect for trailing slash
@app.get("/api/mcp/")
async def redirect_mcp_with_slash():
    """Redirect /api/mcp/ to /api/mcp"""
    return RedirectResponse(url="/api/mcp", status_code=307)


# Add info endpoint for GET requests to /api/mcp
@app.get("/api/mcp")
async def mcp_info():
    """Show info about the MCP endpoint"""
    return JSONResponse({
        "message": "This is the MCP endpoint",
        "info": "Use POST requests with JSON-RPC 2.0 format",
        "example": {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "1.0",
                "capabilities": {},
                "clientInfo": {
                    "name": "YourClient",
                    "version": "1.0"
                }
            },
            "id": 1
        }
    })


# Debug endpoint to show headers
@app.get("/debug-headers")
async def debug_headers(request: Request):
    """Show all headers received by the app"""
    headers_dict = dict(request.headers)
    
    # Highlight important headers
    important_headers = {
        "x-forwarded-access-token": headers_dict.get("x-forwarded-access-token", "NOT PRESENT"),
        "x-forwarded-email": headers_dict.get("x-forwarded-email", "NOT PRESENT"),
        "x-forwarded-user": headers_dict.get("x-forwarded-user", "NOT PRESENT"),
        "authorization": headers_dict.get("authorization", "NOT PRESENT"),
        "cookie": "PRESENT" if headers_dict.get("cookie") else "NOT PRESENT"
    }
    
    return JSONResponse({
        "message": "Headers received by Databricks App",
        "important_headers": important_headers,
        "all_headers": headers_dict,
        "notes": {
            "x-forwarded-access-token": "This is the user's downscoped access token (only available in browser sessions)",
            "x-forwarded-email": "The logged-in user's email",
            "info": "These headers are only present when accessing through a browser after Databricks login"
        }
    })


# Test SQL query endpoint using user's access token
@app.get("/test-sql")
async def test_sql_query(request: Request, query: str = "SHOW CATALOGS"):
    """Test SQL query using user's access token"""
    user_token = request.headers.get("x-forwarded-access-token")
    user_email = request.headers.get("x-forwarded-email", "unknown")
    
    if not user_token:
        return JSONResponse({
            "error": "No user access token found",
            "message": "This endpoint requires browser authentication through Databricks"
        }, status_code=401)
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return JSONResponse({"error": "Failed to create Databricks client"}, status_code=500)
        
        # Execute the SQL query
        response = client.statement_execution.execute_statement(
            statement=query,
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        # Get the result
        if hasattr(response, 'statement_id') and response.statement_id:
            result = client.statement_execution.get_statement(statement_id=response.statement_id)
            
            if hasattr(result, 'result') and result.result:
                if hasattr(result.result, 'data_array'):
                    rows = result.result.data_array[:10] if result.result.data_array else []
                    return JSONResponse({
                        "success": True,
                        "user": user_email,
                        "query": query,
                        "results": rows,
                        "message": f"Query executed successfully with user permissions for {user_email}"
                    })
        
        return JSONResponse({
            "success": True,
            "user": user_email,
            "query": query,
            "results": [],
            "message": "Query executed but returned no results"
        })
        
    except Exception as e:
        return JSONResponse({
            "error": f"SQL query failed: {str(e)}",
            "user": user_email,
            "query": query
        }, status_code=500)


# User-specific catalog access endpoint
@app.get("/my-catalogs")
async def my_catalogs(request: Request):
    """List catalogs accessible to the current user using SQL queries"""
    user_token = request.headers.get("x-forwarded-access-token")
    user_email = request.headers.get("x-forwarded-email", "unknown")
    
    if not user_token:
        return JSONResponse({
            "error": "No user access token found",
            "message": "This endpoint requires browser authentication through Databricks"
        }, status_code=401)
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return JSONResponse({"error": "Failed to create Databricks client"}, status_code=500)
        
        # Get catalogs using SQL query
        catalogs_response = client.statement_execution.execute_statement(
            statement="SHOW CATALOGS",
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        catalog_info = []
        
        # Process catalog results
        if hasattr(catalogs_response, 'statement_id') and catalogs_response.statement_id:
            catalogs_result = client.statement_execution.get_statement(statement_id=catalogs_response.statement_id)
            
            if hasattr(catalogs_result, 'result') and catalogs_result.result and hasattr(catalogs_result.result, 'data_array'):
                for catalog_row in catalogs_result.result.data_array:
                    catalog_name = catalog_row[0] if catalog_row else None
                    if catalog_name:
                        catalog_data = {
                            "name": catalog_name,
                            "comment": "No description available via SQL",
                            "schemas": []
                        }
                        
                        # Try to get schemas for this catalog
                        try:
                            schemas_response = client.statement_execution.execute_statement(
                                statement=f"SHOW SCHEMAS IN {catalog_name}",
                                warehouse_id=WAREHOUSE_ID,
                                wait_timeout="30s"
                            )
                            
                            if hasattr(schemas_response, 'statement_id') and schemas_response.statement_id:
                                schemas_result = client.statement_execution.get_statement(statement_id=schemas_response.statement_id)
                                
                                if hasattr(schemas_result, 'result') and schemas_result.result and hasattr(schemas_result.result, 'data_array'):
                                    for schema_row in schemas_result.result.data_array[:3]:  # Limit to first 3 schemas
                                        schema_name = schema_row[0] if schema_row else None
                                        if schema_name:
                                            schema_data = {
                                                "name": schema_name,
                                                "comment": "No description available via SQL"
                                            }
                                            catalog_data["schemas"].append(schema_data)
                                            
                        except Exception as e:
                            catalog_data["schemas_error"] = f"Error getting schemas: {str(e)}"
                        
                        catalog_info.append(catalog_data)
        
        return JSONResponse({
            "success": True,
            "user": user_email,
            "message": f"Showing catalogs accessible to {user_email} (via SQL)",
            "catalogs": catalog_info,
            "total_catalogs": len(catalog_info),
            "method": "SQL queries (compatible with sql scope)"
        })
        
    except Exception as e:
        return JSONResponse({
            "error": f"Failed to list catalogs: {str(e)}",
            "user": user_email
        }, status_code=500)


# Mount the MCP app at /api/mcp (as specified in the documentation)
app.mount("/api/mcp", mcp_app)
