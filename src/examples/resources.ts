import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { readFile, readdir, stat } from 'fs/promises';
import { join, resolve } from 'path';
import { logger } from '../utils/logger.js';
import { paginate } from '../utils/pagination.js';

export function setupExampleResources(server: McpServer): void {
  logger.info('Setting up example resources');
  
  setupStaticResources(server);
  setupDynamicResources(server);
  setupFileSystemResources(server);
  setupApiResources(server);
  setupBinaryResources(server);
}

/**
 * Static Resources - Fixed content that doesn't change
 */
function setupStaticResources(server: McpServer): void {
  // Static text resource
  server.registerResource(
    'static-info',
    'static://server/info',
    {
      title: 'Server Information',
      description: 'Static information about this MCP server',
      mimeType: 'text/plain'
    },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: `MCP Server Template v1.0.0
        
This is a comprehensive MCP server template demonstrating:
- Multiple transport protocols (stdio, HTTP)
- Resource examples with different content types
- Tool implementations with validation
- Prompt templates and sampling
- OAuth 2.0 authentication
- Progress tracking and cancellation
- Pagination support

Built with TypeScript and the latest MCP SDK.`
      }]
    })
  );

  // Static JSON resource
  server.registerResource(
    'static-config',
    'static://server/config',
    {
      title: 'Server Configuration',
      description: 'Current server configuration as JSON',
      mimeType: 'application/json'
    },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: JSON.stringify({
          name: 'mcp-server-template',
          version: '1.0.0',
          features: [
            'stdio-transport',
            'http-transport',
            'cors-support',
            'session-management',
            'oauth-2.0',
            'progress-tracking',
            'cancellation-tokens',
            'pagination'
          ],
          endpoints: {
            health: '/health',
            mcp: '/mcp',
            sse: '/sse',
            messages: '/messages'
          }
        }, null, 2)
      }]
    })
  );
}

/**
 * Dynamic Resources - Content generated based on parameters
 */
function setupDynamicResources(server: McpServer): void {
  // Dynamic greeting resource
  server.registerResource(
    'greeting',
    new ResourceTemplate('greeting://{name}', { list: undefined }),
    {
      title: 'Personal Greeting',
      description: 'Generate a personalized greeting message'
    },
    async (uri, { name }) => ({
      contents: [{
        uri: uri.href,
        text: `Hello, ${name}!
        
Welcome to the MCP Server Template. This is a dynamically generated greeting 
created specifically for you at ${new Date().toISOString()}.

This resource demonstrates how to create dynamic content based on URI parameters.
The parameter 'name' was extracted from the URI template and used to personalize 
this message.`
      }]
    })
  );

  // Dynamic status resource with timestamp
  server.registerResource(
    'status',
    new ResourceTemplate('status://{component}', { list: undefined }),
    {
      title: 'Component Status',
      description: 'Get real-time status of server components'
    },
    async (uri, { component }) => {
      const statuses = {
        server: {
          status: 'running',
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          timestamp: new Date().toISOString()
        },
        transport: {
          status: 'active',
          connections: Math.floor(Math.random() * 10) + 1,
          requestsPerMinute: Math.floor(Math.random() * 100) + 10,
          timestamp: new Date().toISOString()
        },
        auth: {
          status: 'ready',
          activeTokens: Math.floor(Math.random() * 5),
          timestamp: new Date().toISOString()
        },
        database: {
          status: 'connected',
          connectionPool: '5/10',
          responseTime: Math.floor(Math.random() * 50) + 'ms',
          timestamp: new Date().toISOString()
        }
      };

      const componentStatus = statuses[component as keyof typeof statuses] || {
        status: 'unknown',
        message: `Component '${component}' not found`,
        timestamp: new Date().toISOString()
      };

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify(componentStatus, null, 2),
          mimeType: 'application/json'
        }]
      };
    }
  );

  // Math calculation resource
  server.registerResource(
    'math',
    new ResourceTemplate('math://{operation}/{a}/{b}', { list: undefined }),
    {
      title: 'Math Calculator',
      description: 'Perform mathematical operations and show results'
    },
    async (uri, { operation, a, b }) => {
      const numA = parseFloat(a as string);
      const numB = parseFloat(b as string);
      
      if (isNaN(numA) || isNaN(numB)) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Invalid numbers provided',
              a: a,
              b: b
            }, null, 2),
            mimeType: 'application/json'
          }]
        };
      }

      let result: number;
      let operationSymbol: string;

      switch (operation) {
        case 'add':
          result = numA + numB;
          operationSymbol = '+';
          break;
        case 'subtract':
          result = numA - numB;
          operationSymbol = '-';
          break;
        case 'multiply':
          result = numA * numB;
          operationSymbol = '×';
          break;
        case 'divide':
          if (numB === 0) {
            return {
              contents: [{
                uri: uri.href,
                text: JSON.stringify({
                  error: 'Division by zero is not allowed'
                }, null, 2),
                mimeType: 'application/json'
              }]
            };
          }
          result = numA / numB;
          operationSymbol = '÷';
          break;
        default:
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({
                error: `Unknown operation: ${operation}`,
                supportedOperations: ['add', 'subtract', 'multiply', 'divide']
              }, null, 2),
              mimeType: 'application/json'
            }]
          };
      }

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            operation: operation,
            expression: `${numA} ${operationSymbol} ${numB}`,
            result: result,
            timestamp: new Date().toISOString()
          }, null, 2),
          mimeType: 'application/json'
        }]
      };
    }
  );
}

/**
 * File System Resources - Read files and directories from local filesystem
 */
function setupFileSystemResources(server: McpServer): void {
  // File content resource
  server.registerResource(
    'file',
    new ResourceTemplate('file://{path}', { 
      list: undefined
    }),
    {
      title: 'File Content',
      description: 'Read content from local files (relative to server root)'
    },
    async (uri, { path }) => {
      const pathStr = path as string;
      try {
        // Security: restrict to current directory and subdirectories
        const safePath = resolve(join(process.cwd(), pathStr));
        if (!safePath.startsWith(process.cwd())) {
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({
                error: 'Access denied: Path outside allowed directory',
                path: pathStr
              }, null, 2),
              mimeType: 'application/json'
            }]
          };
        }

        const stats = await stat(safePath);
        
        if (stats.isDirectory()) {
          const files = await readdir(safePath);
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({
                type: 'directory',
                path: pathStr,
                contents: files.map(file => ({
                  name: file,
                  uri: `file://${pathStr}/${file}`
                })),
                count: files.length
              }, null, 2),
              mimeType: 'application/json'
            }]
          };
        } else {
          const content = await readFile(safePath, 'utf-8');
          const mimeType = getMimeTypeFromExtension(safePath);
          
          return {
            contents: [{
              uri: uri.href,
              text: content,
              mimeType: mimeType
            }]
          };
        }
      } catch (error) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Failed to read file',
              message: (error as Error).message,
              path: pathStr
            }, null, 2),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );
}

/**
 * API-based Resources - Fetch data from external APIs with pagination
 */
function setupApiResources(server: McpServer): void {
  // Mock API data resource with pagination
  server.registerResource(
    'api-users',
    new ResourceTemplate('api://users?page={page}&size={size}', { 
      list: undefined
    }),
    {
      title: 'User Data API',
      description: 'Paginated user data from mock API'
    },
    async (uri, { page = '1', size = '10' }) => {
      try {
        // Generate mock user data
        const totalUsers = 1000;
        const pageNum = Math.max(1, parseInt(page as string, 10));
        const pageSize = Math.min(100, Math.max(1, parseInt(size as string, 10)));
        
        const startId = (pageNum - 1) * pageSize + 1;
        const endId = Math.min(startId + pageSize - 1, totalUsers);
        
        const users = [];
        for (let id = startId; id <= endId; id++) {
          users.push({
            id: id,
            name: `User ${id}`,
            email: `user${id}@example.com`,
            role: id % 3 === 0 ? 'admin' : id % 3 === 1 ? 'user' : 'viewer',
            createdAt: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
            active: Math.random() > 0.2
          });
        }

        const paginatedResult = paginate(users, { page: pageNum, size: pageSize });

        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              users: paginatedResult.data,
              pagination: {
                ...paginatedResult.pagination,
                total: totalUsers
              },
              meta: {
                totalUsers: totalUsers,
                requestedPage: pageNum,
                requestedSize: pageSize,
                timestamp: new Date().toISOString()
              }
            }, null, 2),
            mimeType: 'application/json'
          }]
        };
      } catch (error) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Failed to fetch user data',
              message: (error as Error).message
            }, null, 2),
            mimeType: 'application/json'
          }]
        };
      }
    }
  );

  // Weather data resource (mock)
  server.registerResource(
    'weather',
    new ResourceTemplate('weather://{location}', { list: undefined }),
    {
      title: 'Weather Information',
      description: 'Get weather data for a specific location (mock data)'
    },
    async (uri, { location }) => {
      // Generate mock weather data
      const conditions = ['sunny', 'cloudy', 'rainy', 'snowy', 'stormy'];
      const condition = conditions[Math.floor(Math.random() * conditions.length)];
      const temperature = Math.floor(Math.random() * 40) - 10; // -10 to 30°C
      const humidity = Math.floor(Math.random() * 100);
      const windSpeed = Math.floor(Math.random() * 30);

      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            location: location,
            condition: condition,
            temperature: `${temperature}°C`,
            humidity: `${humidity}%`,
            windSpeed: `${windSpeed} km/h`,
            timestamp: new Date().toISOString(),
            note: 'This is mock weather data for demonstration purposes'
          }, null, 2),
          mimeType: 'application/json'
        }]
      };
    }
  );
}

/**
 * Binary Resources - Demonstrate binary content handling
 */
function setupBinaryResources(server: McpServer): void {
  // Generate sample binary data (Base64 encoded)
  server.registerResource(
    'binary',
    new ResourceTemplate('binary://{type}/{size}', { list: undefined }),
    {
      title: 'Binary Data Generator',
      description: 'Generate sample binary data of specified type and size'
    },
    async (uri, { type, size }) => {
      const sizeBytes = Math.min(10000, Math.max(1, parseInt(size as string, 10))); // Limit to 10KB
      
      switch (type) {
        case 'random':
          // Generate random binary data
          const randomData = Buffer.alloc(sizeBytes);
          for (let i = 0; i < sizeBytes; i++) {
            randomData[i] = Math.floor(Math.random() * 256);
          }
          return {
            contents: [{
              uri: uri.href,
              blob: randomData.toString('base64'),
              mimeType: 'application/octet-stream'
            }]
          };

        case 'image':
          // Generate a simple bitmap-like pattern
          const imageHeader = Buffer.from([
            0x42, 0x4D, // BMP signature
            0x36, 0x00, 0x00, 0x00, // File size (placeholder)
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x36, 0x00, 0x00, 0x00, // Offset to pixel data
          ]);
          const imageData = Buffer.concat([imageHeader, Buffer.alloc(sizeBytes - imageHeader.length, 0x00)]);
          
          return {
            contents: [{
              uri: uri.href,
              blob: imageData.toString('base64'),
              mimeType: 'image/bmp'
            }]
          };

        default:
          return {
            contents: [{
              uri: uri.href,
              text: JSON.stringify({
                error: `Unknown binary type: ${type}`,
                supportedTypes: ['random', 'image']
              }, null, 2),
              mimeType: 'application/json'
            }]
          };
      }
    }
  );
}

/**
 * Helper function to determine MIME type from file extension
 */
function getMimeTypeFromExtension(filePath: string): string {
  const extension = filePath.split('.').pop()?.toLowerCase();
  
  const mimeTypes: Record<string, string> = {
    'txt': 'text/plain',
    'md': 'text/markdown',
    'json': 'application/json',
    'js': 'application/javascript',
    'ts': 'text/typescript',
    'html': 'text/html',
    'css': 'text/css',
    'xml': 'application/xml',
    'csv': 'text/csv',
    'log': 'text/plain',
    'yml': 'application/x-yaml',
    'yaml': 'application/x-yaml'
  };

  return mimeTypes[extension || ''] || 'text/plain';
}