# Databricks MCP Client with Entra ID Authentication
# Eliminates X-Forwarded-Access-Token dependency

param([switch]$Interactive)

$SERVER_URL = 'https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/mcp'
$ENTRA_TENANT_ID = '728e54cf-7d26-49fe-ac9b-b96c5bf26cb8'  # Your organization's tenant ID
$ENTRA_CLIENT_ID = 'eca83914-a51d-4adb-8bc6-8471cd522c3a'  # From Databricks App OAuth2 Client ID
$REDIRECT_URI = 'http://localhost:8080/callback'
$SCOPE = 'https://adb-1761712055023179.19.azuredatabricks.net/.default'

# Token storage
$TOKEN_FILE = "$env:TEMP\databricks_entra_token.json"

# Enable TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Load required assemblies
Add-Type -AssemblyName System.Web

function Get-StoredToken {
    if (Test-Path $TOKEN_FILE) {
        try {
            $tokenData = Get-Content $TOKEN_FILE -Raw | ConvertFrom-Json
            if ($tokenData.expires_at -gt (Get-Date).AddMinutes(5)) {
                return $tokenData.access_token
            }
        }
        catch {
            # Invalid token file
        }
    }
    return $null
}

function Save-Token {
    param([string]$AccessToken, [int]$ExpiresIn = 3600)
    
    $tokenData = @{
        access_token = $AccessToken
        expires_at = (Get-Date).AddSeconds($ExpiresIn)
        obtained_at = Get-Date
    }
    
    $tokenData | ConvertTo-Json | Set-Content $TOKEN_FILE
}

function Start-EntraIdFlow {
    Write-Host "Starting Entra ID authentication..." -ForegroundColor Cyan
    
    try {
        # Generate PKCE parameters
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $codeVerifier = -join ((1..128) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        $codeChallenge = [System.Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($codeVerifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        
        # Build Entra ID authorization URL
        $authParams = @{
            'response_type' = 'code'
            'client_id' = $ENTRA_CLIENT_ID
            'redirect_uri' = $REDIRECT_URI
            'scope' = $SCOPE
            'code_challenge' = $codeChallenge
            'code_challenge_method' = 'S256'
            'state' = [System.Guid]::NewGuid().ToString()
        }
        
        $paramString = ($authParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'
        $authUrl = "https://login.microsoftonline.com/$ENTRA_TENANT_ID/oauth2/v2.0/authorize?$paramString"
        
        Write-Host "Opening browser for Entra ID login..." -ForegroundColor Yellow
        Start-Process $authUrl
        
        # Start local HTTP server for callback
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("$REDIRECT_URI/")
        $listener.Start()
        
        Write-Host "Waiting for Entra ID callback..." -ForegroundColor Yellow
        
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $queryString = $request.Url.Query
        $params = [System.Web.HttpUtility]::ParseQueryString($queryString)
        
        $authCode = $params['code']
        $error = $params['error']
        
        if ($error) {
            $response.StatusCode = 400
            $responseString = @"
<html><body><h1>Entra ID Error</h1><p>$error</p></body></html>
"@
        }
        elseif (-not $authCode) {
            $response.StatusCode = 400
            $responseString = @"
<html><body><h1>Missing Authorization Code</h1></body></html>
"@
        }
        else {
            Write-Host "Exchanging Entra ID code for token..." -ForegroundColor Yellow
            
            # Exchange code for Entra ID token
            $tokenParams = @{
                'grant_type' = 'authorization_code'
                'client_id' = $ENTRA_CLIENT_ID
                'code' = $authCode
                'redirect_uri' = $REDIRECT_URI
                'code_verifier' = $codeVerifier
                'scope' = $SCOPE
            }
            
            try {
                $tokenUrl = "https://login.microsoftonline.com/$ENTRA_TENANT_ID/oauth2/v2.0/token"
                $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenParams -ContentType 'application/x-www-form-urlencoded'
                
                # Now exchange Entra ID token for Databricks token
                Write-Host "Exchanging Entra ID token for Databricks token..." -ForegroundColor Yellow
                $databricksToken = Exchange-EntraForDatabricks -EntraToken $tokenResponse.access_token
                
                Save-Token -AccessToken $databricksToken -ExpiresIn $tokenResponse.expires_in
                
                $response.StatusCode = 200
                $responseString = @"
<html><body><h1>Authentication Successful!</h1><p>You can close this window.</p></body></html>
"@
                
                Write-Host "Entra ID authentication completed!" -ForegroundColor Green
                return $databricksToken
            }
            catch {
                Write-Host "Token exchange failed: $($_.Exception.Message)" -ForegroundColor Red
                $response.StatusCode = 500
                $responseString = @"
<html><body><h1>Token Exchange Failed</h1><p>$($_.Exception.Message)</p></body></html>
"@
            }
        }
        
        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseString)
        $response.ContentLength64 = $responseBytes.Length
        $response.OutputStream.Write($responseBytes, 0, $responseBytes.Length)
        $response.OutputStream.Close()
        $listener.Stop()
        
    }
    catch {
        Write-Host "Entra ID flow failed: $($_.Exception.Message)" -ForegroundColor Red
        if ($listener) { $listener.Stop() }
    }
    
    return $null
}

function Exchange-EntraForDatabricks {
    param([string]$EntraToken)
    
    # Use your MCP server's token exchange endpoint
    $exchangeUrl = "https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/exchange-token"
    
    try {
        $exchangeResponse = Invoke-RestMethod -Uri $exchangeUrl -Method POST -Headers @{
            'Authorization' = "Bearer $EntraToken"
            'Content-Type' = 'application/json'
        } -Body (@{
            'grant_type' = 'urn:ietf:params:oauth:grant-type:token-exchange'
            'subject_token' = $EntraToken
            'subject_token_type' = 'urn:ietf:params:oauth:token-type:access_token'
            'requested_token_type' = 'urn:ietf:params:oauth:token-type:access_token'
        } | ConvertTo-Json)
        
        return $exchangeResponse.access_token
    }
    catch {
        Write-Host "Databricks token exchange failed: $($_.Exception.Message)" -ForegroundColor Red
        # Fallback: use Entra token directly (your server should handle both)
        return $EntraToken
    }
}

function Get-AccessToken {
    # CRITICAL: Must return quickly for Claude Desktop
    $token = Get-StoredToken
    if ($token) {
        return $token
    }
    
    # No cached token - check if we can use environment variable as fallback
    if ($env:DATABRICKS_TOKEN) {
        Write-Host "Using DATABRICKS_TOKEN environment variable" -ForegroundColor Yellow
        return $env:DATABRICKS_TOKEN
    }
    
    # Show helpful message and exit gracefully
    Write-Host "No cached Entra ID token found." -ForegroundColor Red
    Write-Host "Please run this script interactively first to authenticate:" -ForegroundColor Yellow
    Write-Host "   powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$($MyInvocation.MyCommand.Path)' -Interactive" -ForegroundColor Cyan
    Write-Host "Or set DATABRICKS_TOKEN environment variable as fallback" -ForegroundColor Yellow
    
    return $null
}

function Invoke-MakeRequest {
    param([object]$RequestBody, [string]$AccessToken)
    
    try {
        $postData = $RequestBody | ConvertTo-Json -Depth 10 -Compress
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
            'User-Agent' = 'Databricks-MCP-Client-Entra/1.0'
        }
        
        $response = Invoke-RestMethod -Uri $SERVER_URL -Method POST -Headers $headers -Body $postData
        return $response
    }
    catch {
        throw "HTTP Error: $($_.Exception.Message)"
    }
}

# Check if running in interactive mode for initial authentication

if ($Interactive) {
    Write-Host "Interactive Entra ID Authentication Mode" -ForegroundColor Cyan
    Write-Host "This will authenticate you and cache the token for MCP use." -ForegroundColor Yellow
    
    $token = Start-EntraIdFlow
    if ($token) {
        Write-Host "Authentication successful! Token cached." -ForegroundColor Green
        Write-Host "You can now use Claude Desktop with this MCP server." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Authentication failed." -ForegroundColor Red
        exit 1
    }
}

# Main execution
# Get access token BEFORE starting MCP processing
# This is critical - Claude Desktop expects immediate responses
$ACCESS_TOKEN = Get-AccessToken

if (-not $ACCESS_TOKEN) {
    Write-Host "Failed to obtain access token. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host "Databricks token ready - starting MCP processing" -ForegroundColor Green

# Main MCP processing loop
Write-Host "Ready to process MCP requests with Entra ID authentication" -ForegroundColor Green

while ($true) {
    $inputLine = [Console]::ReadLine()
    
    if ($inputLine -eq $null) {
        break
    }
    
    try {
        $request = $inputLine.Trim() | ConvertFrom-Json
        $requestId = $request.id
        
        if (-not $request.jsonrpc -or $request.jsonrpc -ne "2.0") {
            throw "Invalid JSON-RPC version"
        }
        
        # Handle notifications
        if ($requestId -eq $null) {
            if ($request.method -eq 'notifications/initialized') {
                continue
            }
            throw "Missing request ID"
        }
        
        # Handle initialize
        if ($request.method -eq 'initialize') {
            $initResponse = @{
                jsonrpc = "2.0"
                result = @{
                    protocolVersion = "2024-11-05"
                    serverInfo = @{
                        name = "databricks-mcp-entra"
                        version = "1.0.0"
                    }
                    capabilities = @{
                        tools = @{}
                    }
                }
                id = $requestId
            }
            Write-Output ($initResponse | ConvertTo-Json -Depth 10 -Compress)
            continue
        }
        
        # Forward to MCP server
        $response = Invoke-MakeRequest -RequestBody $request -AccessToken $ACCESS_TOKEN
        
        $finalResponse = @{
            jsonrpc = "2.0"
            id = $requestId
        }
        
        if ($response.PSObject.Properties.Name -contains 'result') {
            $finalResponse.result = $response.result
        } elseif ($response.PSObject.Properties.Name -contains 'error') {
            $finalResponse.error = $response.error
        } else {
            $finalResponse.result = $response
        }
        
        Write-Output ($finalResponse | ConvertTo-Json -Depth 10 -Compress)
    }
    catch {
        $errorResponse = @{
            jsonrpc = "2.0"
            error = @{
                code = -32603
                message = $_.Exception.Message
            }
            id = $requestId
        }
        Write-Output ($errorResponse | ConvertTo-Json -Depth 10 -Compress)
    }
}