# Databricks MCP Client - PowerShell Version
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