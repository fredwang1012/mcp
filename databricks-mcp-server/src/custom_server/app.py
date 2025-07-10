from pathlib import Path
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from databricks.sdk import WorkspaceClient
import os
import json
from typing import Dict, Any

STATIC_DIR = Path(__file__).parent / "static"

# Create an MCP server with user authentication context
mcp = FastMCP(
    name="Unity Catalog SQL MCP Server",
    stateless_http = True,  # Use stateless HTTP mode for simplicity
    )

# Databricks configuration
DATABRICKS_HOST = os.environ.get("DATABRICKS_HOST", "https://adb-1761712055023179.19.azuredatabricks.net")
WAREHOUSE_ID = os.environ.get("DATABRICKS_WAREHOUSE_ID", "a85c850e7621e163")

# Global variable to store current request context for MCP tools
_current_request: Request | None = None

def get_current_user_token() -> str | None:
    """Get the current user's OAuth token from request context"""
    if _current_request:
        # Try Authorization header first (for Bearer token auth)
        auth_header = _current_request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header.replace("Bearer ", "").strip()
        
        # Fallback to x-forwarded-access-token (for browser sessions)
        return _current_request.headers.get("x-forwarded-access-token")
    
    # If no context, try environment variables as fallback
    return os.environ.get("DATABRICKS_ACCESS_TOKEN")


def get_current_user_email() -> str:
    """Get the current user's email from request context"""
    if _current_request:
        return _current_request.headers.get("x-forwarded-email", "unknown")
    return "unknown"


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


# Tool definitions - use decorators for proper registration
@mcp.tool()
def query_sql(query: str, limit: int = 100) -> str:
    """Execute a SQL query against Unity Catalog using user's permissions
    
    Args:
        query: SQL query to execute
        limit: Maximum number of rows to return (default: 100)
    
    Returns:
        Query results formatted as JSON string
    """
    user_token = get_current_user_token()
    user_email = get_current_user_email()
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return json.dumps({
                "error": "Failed to create Databricks client",
                "user": user_email
            })
        
        # Execute the statement
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
                    rows = result.result.data_array[:limit] if result.result.data_array else []
                    columns = []
                    if hasattr(result.result, 'schema') and result.result.schema:
                        columns = [col.name for col in result.result.schema.columns] if result.result.schema.columns else []
                    
                    return json.dumps({
                        "success": True,
                        "user": user_email,
                        "query": query,
                        "columns": columns,
                        "rows": rows,
                        "row_count": len(rows),
                        "limited": len(rows) == limit
                    }, indent=2)
                    
        return json.dumps({
            "success": True,
            "user": user_email,
            "query": query,
            "rows": [],
            "message": "Query executed but returned no results"
        })
            
    except Exception as e:
        return json.dumps({
            "error": f"SQL query failed: {str(e)}",
            "user": user_email,
            "query": query
        })


@mcp.tool()
def list_catalogs() -> str:
    """List all Unity Catalog catalogs accessible to the current user
    
    Returns:
        List of catalogs in JSON format
    """
    user_token = get_current_user_token()
    user_email = get_current_user_email()
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return json.dumps({"error": "Failed to create Databricks client"})
        
        # Get catalogs using SQL query (more reliable with user permissions)
        response = client.statement_execution.execute_statement(
            statement="SHOW CATALOGS",
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        catalogs = []
        if hasattr(response, 'statement_id') and response.statement_id:
            result = client.statement_execution.get_statement(statement_id=response.statement_id)
            
            if hasattr(result, 'result') and result.result and hasattr(result.result, 'data_array'):
                for catalog_row in result.result.data_array:
                    catalog_name = catalog_row[0] if catalog_row else None
                    if catalog_name:
                        catalogs.append(catalog_name)
        
        return json.dumps({
            "success": True,
            "user": user_email,
            "catalogs": catalogs,
            "count": len(catalogs)
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Failed to list catalogs: {str(e)}",
            "user": user_email
        })


@mcp.tool()
def list_schemas(catalog: str) -> str:
    """List schemas in a specific catalog
    
    Args:
        catalog: Name of the catalog
        
    Returns:
        List of schemas in JSON format
    """
    user_token = get_current_user_token()
    user_email = get_current_user_email()
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return json.dumps({"error": "Failed to create Databricks client"})
        
        response = client.statement_execution.execute_statement(
            statement=f"SHOW SCHEMAS IN {catalog}",
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        schemas = []
        if hasattr(response, 'statement_id') and response.statement_id:
            result = client.statement_execution.get_statement(statement_id=response.statement_id)
            
            if hasattr(result, 'result') and result.result and hasattr(result.result, 'data_array'):
                for schema_row in result.result.data_array:
                    schema_name = schema_row[0] if schema_row else None
                    if schema_name:
                        schemas.append(schema_name)
        
        return json.dumps({
            "success": True,
            "user": user_email,
            "catalog": catalog,
            "schemas": schemas,
            "count": len(schemas)
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Failed to list schemas in catalog '{catalog}': {str(e)}",
            "user": user_email,
            "catalog": catalog
        })


@mcp.tool()
def list_tables(catalog: str, schema: str) -> str:
    """List tables in a specific schema
    
    Args:
        catalog: Name of the catalog
        schema: Name of the schema
        
    Returns:
        List of tables in JSON format
    """
    user_token = get_current_user_token()
    user_email = get_current_user_email()
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return json.dumps({"error": "Failed to create Databricks client"})
        
        response = client.statement_execution.execute_statement(
            statement=f"SHOW TABLES IN {catalog}.{schema}",
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        tables = []
        if hasattr(response, 'statement_id') and response.statement_id:
            result = client.statement_execution.get_statement(statement_id=response.statement_id)
            
            if hasattr(result, 'result') and result.result and hasattr(result.result, 'data_array'):
                for table_row in result.result.data_array:
                    if table_row and len(table_row) >= 2:
                        table_name = table_row[1]  # Second column is table name
                        table_type = table_row[3] if len(table_row) > 3 else "TABLE"  # Fourth column is table type
                        if table_name:
                            tables.append({
                                "name": table_name,
                                "type": table_type
                            })
        
        return json.dumps({
            "success": True,
            "user": user_email,
            "catalog": catalog,
            "schema": schema,
            "tables": tables,
            "count": len(tables)
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Failed to list tables in {catalog}.{schema}: {str(e)}",
            "user": user_email,
            "catalog": catalog,
            "schema": schema
        })


@mcp.tool()
def describe_table(catalog: str, schema: str, table: str) -> str:
    """Get detailed information about a table including schema and metadata
    
    Args:
        catalog: Name of the catalog
        schema: Name of the schema
        table: Name of the table
        
    Returns:
        Table description in JSON format
    """
    user_token = get_current_user_token()
    user_email = get_current_user_email()
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return json.dumps({"error": "Failed to create Databricks client"})
        
        full_table_name = f"{catalog}.{schema}.{table}"
        
        response = client.statement_execution.execute_statement(
            statement=f"DESCRIBE TABLE EXTENDED {full_table_name}",
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        columns = []
        
        if hasattr(response, 'statement_id') and response.statement_id:
            result = client.statement_execution.get_statement(statement_id=response.statement_id)
            
            if hasattr(result, 'result') and result.result and hasattr(result.result, 'data_array'):
                for row in result.result.data_array:
                    if row and len(row) >= 3:
                        col_name = row[0]
                        data_type = row[1]
                        comment = row[2]
                        
                        if col_name and not col_name.startswith("#"):  # Skip metadata rows
                            if col_name == "":  # Properties section starts
                                break
                            columns.append({
                                "name": col_name,
                                "type": data_type,
                                "comment": comment
                            })
        
        return json.dumps({
            "success": True,
            "user": user_email,
            "table": full_table_name,
            "columns": columns,
            "column_count": len(columns)
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Failed to describe table {catalog}.{schema}.{table}: {str(e)}",
            "user": user_email,
            "table": f"{catalog}.{schema}.{table}"
        })


@mcp.tool()
def search_tables(search_term: str, limit: int = 20) -> str:
    """Search for tables across all accessible catalogs by name pattern
    
    Args:
        search_term: Search pattern (will be used in LIKE '%term%')
        limit: Maximum number of results to return
        
    Returns:
        Search results in JSON format
    """
    user_token = get_current_user_token()
    user_email = get_current_user_email()
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return json.dumps({"error": "Failed to create Databricks client"})
        
        # Get list of catalogs first
        catalogs_response = client.statement_execution.execute_statement(
            statement="SHOW CATALOGS",
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        catalogs = []
        if hasattr(catalogs_response, 'statement_id') and catalogs_response.statement_id:
            result = client.statement_execution.get_statement(statement_id=catalogs_response.statement_id)
            if hasattr(result, 'result') and result.result and hasattr(result.result, 'data_array'):
                for catalog_row in result.result.data_array:
                    if catalog_row and catalog_row[0]:
                        catalogs.append(catalog_row[0])
        
        # Search in each catalog
        matching_tables = []
        
        for catalog in catalogs[:10]:  # Limit catalog search
            try:
                schemas_response = client.statement_execution.execute_statement(
                    statement=f"SHOW SCHEMAS IN {catalog}",
                    warehouse_id=WAREHOUSE_ID,
                    wait_timeout="30s"
                )
                
                schemas = []
                if hasattr(schemas_response, 'statement_id') and schemas_response.statement_id:
                    schemas_result = client.statement_execution.get_statement(statement_id=schemas_response.statement_id)
                    if hasattr(schemas_result, 'result') and schemas_result.result and hasattr(schemas_result.result, 'data_array'):
                        for schema_row in schemas_result.result.data_array:
                            if schema_row and schema_row[0]:
                                schemas.append(schema_row[0])
                
                for schema in schemas[:5]:  # Limit schema search
                    try:
                        tables_response = client.statement_execution.execute_statement(
                            statement=f"SHOW TABLES IN {catalog}.{schema}",
                            warehouse_id=WAREHOUSE_ID,
                            wait_timeout="30s"
                        )
                        
                        if hasattr(tables_response, 'statement_id') and tables_response.statement_id:
                            tables_result = client.statement_execution.get_statement(statement_id=tables_response.statement_id)
                            if hasattr(tables_result, 'result') and tables_result.result and hasattr(tables_result.result, 'data_array'):
                                for table_row in tables_result.result.data_array:
                                    if table_row and len(table_row) >= 2:
                                        table_name = table_row[1]
                                        if table_name and search_term.lower() in table_name.lower():
                                            matching_tables.append({
                                                "catalog": catalog,
                                                "schema": schema,
                                                "table": table_name,
                                                "full_name": f"{catalog}.{schema}.{table_name}"
                                            })
                                            if len(matching_tables) >= limit:
                                                break
                    except:
                        pass
                        continue
                    
                    if len(matching_tables) >= limit:
                        break
            except:
                pass
                continue
                
            if len(matching_tables) >= limit:
                break
        
        return json.dumps({
            "success": True,
            "user": user_email,
            "search_term": search_term,
            "results": matching_tables,
            "count": len(matching_tables),
            "limited": len(matching_tables) == limit
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Failed to search tables: {str(e)}",
            "user": user_email,
            "search_term": search_term
        })


# Enhanced Unity Catalog resource
@mcp.resource("unity-catalog://overview")
def get_unity_catalog_overview() -> str:
    """Get comprehensive overview of accessible Unity Catalog resources"""
    user_token = get_current_user_token()
    user_email = get_current_user_email()
    
    try:
        client = get_databricks_client(user_token=user_token)
        if not client:
            return "Error: Failed to create Databricks client"
        
        # Get catalogs using SQL query
        response = client.statement_execution.execute_statement(
            statement="SHOW CATALOGS",
            warehouse_id=WAREHOUSE_ID,
            wait_timeout="30s"
        )
        
        overview = f"Unity Catalog Overview for {user_email}\n"
        overview += "=" * 50 + "\n\n"
        
        catalog_count = 0
        if hasattr(response, 'statement_id') and response.statement_id:
            result = client.statement_execution.get_statement(statement_id=response.statement_id)
            
            if hasattr(result, 'result') and result.result and hasattr(result.result, 'data_array'):
                catalog_count = len(result.result.data_array)
                overview += f"📊 Total Accessible Catalogs: {catalog_count}\n\n"
                
                for i, catalog_row in enumerate(result.result.data_array[:10]):  # Show first 10
                    catalog_name = catalog_row[0] if catalog_row else None
                    if catalog_name:
                        overview += f"📁 {i+1}. {catalog_name}\n"
                        
                        # Try to get a few schemas
                        try:
                            schemas_response = client.statement_execution.execute_statement(
                                statement=f"SHOW SCHEMAS IN {catalog_name}",
                                warehouse_id=WAREHOUSE_ID,
                                wait_timeout="15s"
                            )
                            
                            if hasattr(schemas_response, 'statement_id') and schemas_response.statement_id:
                                schemas_result = client.statement_execution.get_statement(statement_id=schemas_response.statement_id)
                                if hasattr(schemas_result, 'result') and schemas_result.result and hasattr(schemas_result.result, 'data_array'):
                                    schema_count = len(schemas_result.result.data_array)
                                    overview += f"   📂 Schemas: {schema_count}\n"
                                    
                                    for schema_row in schemas_result.result.data_array[:3]:  # Show first 3 schemas
                                        schema_name = schema_row[0] if schema_row else None
                                        if schema_name:
                                            overview += f"      • {schema_name}\n"
                                            
                        except Exception as e:
                            overview += f"   ❌ Error accessing schemas: {str(e)[:50]}...\n"
                        
                        overview += "\n"
                
                if catalog_count > 10:
                    overview += f"... and {catalog_count - 10} more catalogs\n\n"
        
        overview += f"🔍 Use the MCP tools to explore your data:\n"
        overview += f"   • query_sql() - Execute SQL queries\n"
        overview += f"   • list_catalogs() - List all catalogs\n"
        overview += f"   • list_schemas(catalog) - List schemas\n"
        overview += f"   • list_tables(catalog, schema) - List tables\n"
        overview += f"   • describe_table(catalog, schema, table) - Table details\n"
        overview += f"   • search_tables(term) - Search for tables\n"
        
        return overview
        
    except Exception as e:
        return f"Error accessing Unity Catalog: {str(e)}"


# Create the streamable HTTP app AFTER all tools and resources are defined
mcp_app = mcp.streamable_http_app()

# Create FastAPI app
app = FastAPI(
    lifespan=mcp_app.router.lifespan_context
)

# Create a router for non-MCP endpoints
from fastapi import APIRouter
router = APIRouter()

# Middleware to set request context for ALL requests
@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Set the current request context for MCP tools"""
    global _current_request
    _current_request = request
    try:
        response = await call_next(request)
        return response
    finally:
        _current_request = None


# Move all endpoints to router
@router.get("/ui", include_in_schema=False)
async def serve_index():
    return FileResponse(STATIC_DIR / "index.html")

@router.get("/ui/")
async def redirect_ui():
    return RedirectResponse(url="/ui", status_code=301)

@router.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return JSONResponse({"status": "healthy", "service": "Unity Catalog MCP Server"})

@router.get("/debug-headers")
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
@router.get("/test-sql")
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
@router.get("/my-catalogs")
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


# Add debug endpoint to show available routes  
@router.get("/debug-routes")
async def debug_routes():
    """Show all available routes"""
    routes = []
    for route in app.routes:
        if hasattr(route, 'path'):
            routes.append({
                "path": route.path,
                "methods": list(route.methods) if hasattr(route, 'methods') else [],
                "name": route.name if hasattr(route, 'name') else "N/A"
            })
    return JSONResponse({
        "message": "Available routes",
        "routes": routes,
        "mcp_note": "MCP should be available at the mounted path"
    })


# Debug endpoint to check MCP tools
@router.get("/debug-mcp-tools")
async def debug_mcp_tools():
    """Show registered MCP tools"""
    try:
        tools_info = []
        
        # Check the tool manager instead
        if hasattr(mcp, '_tool_manager'):
            # Try different ways to access tools
            if hasattr(mcp._tool_manager, 'tools'):
                for tool_name, tool_info in mcp._tool_manager.tools.items():
                    tools_info.append({
                        "name": tool_name,
                        "info": str(tool_info)
                    })
            elif hasattr(mcp._tool_manager, '_tools'):
                for tool_name, tool_info in mcp._tool_manager._tools.items():
                    tools_info.append({
                        "name": tool_name,
                        "info": str(tool_info)
                    })
        
        # Also check if there's a _mcp_server attribute
        if hasattr(mcp, '_mcp_server'):
            server_info = {
                "has_mcp_server": True,
                "server_type": str(type(mcp._mcp_server))
            }
        else:
            server_info = {"has_mcp_server": False}
        
        return JSONResponse({
            "message": "MCP Tools Debug Info",
            "tools_count": len(tools_info),
            "tools": tools_info,
            "server_info": server_info,
            "tool_manager_attrs": dir(mcp._tool_manager) if hasattr(mcp, '_tool_manager') else [],
            "mcp_attributes": dir(mcp),
            "stateless_http": mcp.settings.stateless_http if hasattr(mcp, 'settings') else 'unknown'
        })
    except Exception as e:
        return JSONResponse({
            "error": f"Failed to debug MCP tools: {str(e)}",
            "type": str(type(e))
        })


# Debug endpoint to check MCP app routes
@router.get("/debug-mcp-routes")
async def debug_mcp_routes():
    """Debug MCP app routes"""
    routes = []
    if hasattr(mcp_app, 'routes'):
        for route in mcp_app.routes:
            routes.append({
                "path": getattr(route, 'path', 'N/A'),
                "methods": list(getattr(route, 'methods', [])),
                "name": getattr(route, 'name', 'N/A')
            })
    
    # Also check router routes
    router_routes = []
    if hasattr(mcp_app, 'router') and hasattr(mcp_app.router, 'routes'):
        for route in mcp_app.router.routes:
            router_routes.append({
                "path": getattr(route, 'path', 'N/A'),
                "methods": list(getattr(route, 'methods', [])),
                "name": getattr(route, 'name', 'N/A')
            })
    
    return JSONResponse({
        "mcp_app_type": str(type(mcp_app)),
        "has_routes": hasattr(mcp_app, 'routes'),
        "routes": routes,
        "router_routes": router_routes,
        "mcp_app_attrs": dir(mcp_app)
    })


# Include all regular routes
app.include_router(router)

# Mount MCP app at root (last, so it doesn't override other routes)
app.mount("/mcp", mcp_app, name="mcp")
