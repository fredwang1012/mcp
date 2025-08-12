#!/usr/bin/env node

const https = require('https');
const readline = require('readline');

const SERVER_URL = 'https://databricks-mcp-server-1761712055023179.19.azure.databricksapps.com/mcp';
const TOKEN = process.env.BEARER_TOKEN;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

function makeRequest(requestBody) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(requestBody);
    
    const options = {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0'
      }
    };

    const req = https.request(SERVER_URL, options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        // Check HTTP status first
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          return;
        }
        
        if (!data || data.trim() === '') {
          reject(new Error('Empty response from server'));
          return;
        }
        
        try {
          const response = JSON.parse(data);
          resolve(response);
        } catch (e) {
          reject(new Error(`Invalid JSON response: ${data.substring(0, 200)}...`));
        }
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.write(postData);
    req.end();
  });
}

rl.on('line', async (input) => {
  let request = null;
  let requestId = null;
  
  try {
    // Parse the JSON-RPC request
    request = JSON.parse(input.trim());
    requestId = request.id;
    
    // Validate basic JSON-RPC structure
    if (!request.jsonrpc || request.jsonrpc !== "2.0") {
      throw new Error("Invalid JSON-RPC version");
    }
    
    // Handle notifications (no ID, no response needed)
    if (typeof requestId === 'undefined') {
      // Notifications don't need responses
      if (request.method && request.method.startsWith('notifications/')) {
        return; // Just ignore notifications
      }
      throw new Error("Missing request ID");
    }
    
    if (request.method === 'initialize') {
      const initResponse = {
        jsonrpc: "2.0",
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: { name: "databricks-mcp-client", version: "1.0.0" },
          capabilities: { tools: {} }
        },
        id: requestId
      };
      console.log(JSON.stringify(initResponse));
      return;
    }
    
    // Forward request to server
    const response = await makeRequest(request);
    
    // Build a clean JSON-RPC response
    const finalResponse = {
      jsonrpc: "2.0",
      id: requestId
    };
    
    // Copy either result or error, but not both
    if (response.result !== undefined) {
      finalResponse.result = response.result;
    } else if (response.error !== undefined) {
      finalResponse.error = response.error;
    } else {
      // If neither result nor error, treat entire response as result
      finalResponse.result = response;
    }
    
    console.log(JSON.stringify(finalResponse));
    
  } catch (error) {
    // Create a proper JSON-RPC error response
    const errorResponse = {
      jsonrpc: "2.0",
      error: {
        code: -32603,
        message: error.message
      },
      id: requestId
    };
    
    console.log(JSON.stringify(errorResponse));
  }
});