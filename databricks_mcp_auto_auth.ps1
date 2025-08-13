# Databricks MCP with Auto Authentication
# This script runs the MCP client with automatic token management

$MCP_SCRIPT = "C:\Users\FWang\dev\mcp\databricks_mcp_client_entra.ps1"
$TOKEN_FILE = "$env:TEMP\databricks_entra_token.json"

# Enable TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Test-TokenValid {
    if (Test-Path $TOKEN_FILE) {
        try {
            $tokenData = Get-Content $TOKEN_FILE -Raw | ConvertFrom-Json
            if ($tokenData.expires_at -gt (Get-Date).AddMinutes(5)) {
                return $true
            }
        }
        catch {
            # Invalid token file
        }
    }
    return $false
}

# Check if we have a valid token
if (Test-TokenValid) {
    # Token exists and is valid, run MCP normally
    & $MCP_SCRIPT
    exit $LASTEXITCODE
}

# No valid token - try to get one non-interactively first
# Check for environment variable fallback
if ($env:DATABRICKS_TOKEN) {
    # Use environment token and run MCP
    & $MCP_SCRIPT
    exit $LASTEXITCODE
}

# As a last resort, we need interactive auth
# But for Claude Desktop, we need to respond immediately
# So we'll run in "auth required" mode

Write-Host "Authentication required - responding with auth-required mode" -ForegroundColor Yellow

# Send initialize response indicating auth is needed
$initialized = $false

while ($true) {
    $inputLine = [Console]::ReadLine()
    if ($inputLine -eq $null) { break }
    
    try {
        $request = $inputLine.Trim() | ConvertFrom-Json
        $requestId = $request.id
        
        if ($request.method -eq 'initialize') {
            $response = @{
                jsonrpc = "2.0"
                result = @{
                    protocolVersion = "2024-11-05"
                    serverInfo = @{
                        name = "databricks-mcp-auth-required"
                        version = "1.0.0"
                    }
                    capabilities = @{
                        tools = @{}
                    }
                }
                id = $requestId
            }
            Write-Output ($response | ConvertTo-Json -Depth 10 -Compress)
            $initialized = $true
        }
        elseif ($request.method -eq 'notifications/initialized') {
            # Just acknowledge
            continue
        }
        elseif ($request.method -eq 'tools/list') {
            $response = @{
                jsonrpc = "2.0"
                result = @{
                    tools = @(
                        @{
                            name = "authenticate"
                            description = "Please run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$MCP_SCRIPT' -Interactive"
                            inputSchema = @{
                                type = "object"
                                properties = @{}
                            }
                        }
                    )
                }
                id = $requestId
            }
            Write-Output ($response | ConvertTo-Json -Depth 10 -Compress)
        }
        else {
            $response = @{
                jsonrpc = "2.0"
                error = @{
                    code = -32001
                    message = "Authentication required. Run: powershell.exe -File '$MCP_SCRIPT' -Interactive"
                }
                id = $requestId
            }
            Write-Output ($response | ConvertTo-Json -Depth 10 -Compress)
        }
    }
    catch {
        # Invalid JSON, send error
        if ($requestId) {
            $response = @{
                jsonrpc = "2.0"
                error = @{
                    code = -32700
                    message = "Parse error"
                }
                id = $requestId
            }
            Write-Output ($response | ConvertTo-Json -Compress)
        }
    }
}