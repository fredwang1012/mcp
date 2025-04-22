if __name__ == "__main__":
    from databricks.labs.mcp.app import mcp

    mcp.run(transport="sse")
