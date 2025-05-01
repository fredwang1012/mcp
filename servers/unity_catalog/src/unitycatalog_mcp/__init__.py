import uvicorn

def main():
    uvicorn.run(
        "unitycatalog_mcp.server:app",
        port=8000,
        reload=True,
    )
