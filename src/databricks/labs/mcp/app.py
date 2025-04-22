from databricks.labs.mcp.server import DatabricksMCP


mcp = DatabricksMCP("DatabricksMCP")


@mcp.resource("data://current_user")
async def current_user() -> dict:
    """Get the current user from the context."""
    user = mcp.get_current_user()
    if user:
        return {"email": user.email}
    else:
        return {"error": "No user found"}
