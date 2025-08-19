import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { readFile, readdir, stat } from 'fs/promises';
import { join, resolve } from 'path';
import { logger } from '../utils/logger.js';
import { 
  paginate, 
  paginateWithCursor, 
  paginateAsync,
  createResourcePaginationMeta,
  validatePaginationOptions,
  type CursorPaginationItem 
} from '../utils/pagination.js';

export function setupExampleResources(server: McpServer): void {
  logger.info('Setting up example resources');
  
  setupStaticResources(server);
  setupDynamicResources(server);
  setupFileSystemResources(server);
  setupApiResources(server);
  setupBinaryResources(server);
  setupPaginatedResources(server);
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

/**
 * Paginated Resources - Demonstrating different pagination patterns
 */
function setupPaginatedResources(server: McpServer): void {
  // Generate sample dataset for pagination examples
  const generateSampleData = (count: number): CursorPaginationItem[] => {
    return Array.from({ length: count }, (_, i) => ({
      id: `item-${String(i + 1).padStart(3, '0')}`,
      title: `Sample Item ${i + 1}`,
      description: `This is a sample item for demonstrating pagination. Item number ${i + 1} of ${count}.`,
      category: ['technology', 'science', 'business', 'health', 'entertainment'][i % 5],
      status: ['active', 'inactive', 'pending'][i % 3],
      score: Math.floor(Math.random() * 100),
      createdAt: new Date(Date.now() - (Math.random() * 365 * 24 * 60 * 60 * 1000)).toISOString(),
      tags: [`tag-${(i % 10) + 1}`, `category-${(i % 5) + 1}`],
      metadata: {
        priority: ['low', 'medium', 'high'][i % 3],
        department: ['engineering', 'marketing', 'sales', 'support'][i % 4]
      }
    }));
  };

  const sampleData = generateSampleData(150); // 150 items for pagination demos

  // Offset-based pagination resource
  server.registerResource(
    'paginated-offset',
    new ResourceTemplate('paginated://offset/{page?}/{size?}', { 
      list: undefined 
    }),
    {
      title: 'Offset-based Paginated Data',
      description: 'Demonstrates traditional offset-based pagination with page numbers',
      mimeType: 'application/json'
    },
    async (uri) => {
      const url = new URL(uri.href);
      const page = parseInt(url.pathname.split('/')[2] || '1', 10);
      const size = parseInt(url.pathname.split('/')[3] || '10', 10);
      
      const paginationOptions = { page, size };
      const validation = validatePaginationOptions(paginationOptions);
      
      if (!validation.isValid) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Invalid pagination parameters',
              details: validation.errors
            }, null, 2)
          }]
        };
      }
      
      const result = paginate(sampleData, paginationOptions);
      const meta = createResourcePaginationMeta(sampleData.length, page, size);
      
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            ...result,
            metadata: {
              ...meta,
              paginationType: 'offset',
              totalItems: sampleData.length,
              requestedPage: page,
              requestedSize: size,
              examples: {
                nextPage: page < meta.pages ? `paginated://offset/${page + 1}/${size}` : null,
                prevPage: page > 1 ? `paginated://offset/${page - 1}/${size}` : null,
                firstPage: `paginated://offset/1/${size}`,
                lastPage: `paginated://offset/${meta.pages}/${size}`
              }
            }
          }, null, 2)
        }]
      };
    }
  );

  // Cursor-based pagination resource
  server.registerResource(
    'paginated-cursor',
    new ResourceTemplate('paginated://cursor/{cursor?}?size={size?}&sortBy={sortBy?}&sortOrder={sortOrder?}', { 
      list: undefined 
    }),
    {
      title: 'Cursor-based Paginated Data',
      description: 'Demonstrates cursor-based pagination for large datasets',
      mimeType: 'application/json'
    },
    async (uri) => {
      const url = new URL(uri.href);
      const cursor = url.pathname.split('/')[2] === 'null' ? undefined : url.pathname.split('/')[2];
      const size = parseInt(url.searchParams.get('size') || '10', 10);
      const sortBy = url.searchParams.get('sortBy') || 'id';
      const sortOrder = (url.searchParams.get('sortOrder') || 'asc') as 'asc' | 'desc';
      
      const paginationOptions = { cursor, size };
      const validation = validatePaginationOptions(paginationOptions);
      
      if (!validation.isValid) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Invalid pagination parameters',
              details: validation.errors
            }, null, 2)
          }]
        };
      }
      
      try {
        const result = paginateWithCursor(sampleData, { cursor, size, sortBy, sortOrder });
        
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              ...result,
              metadata: {
                paginationType: 'cursor',
                sortBy,
                sortOrder,
                requestedSize: size,
                totalItems: sampleData.length,
                examples: {
                  nextPage: result.pagination.nextCursor 
                    ? `paginated://cursor/${result.pagination.nextCursor}?size=${size}&sortBy=${sortBy}&sortOrder=${sortOrder}` 
                    : null,
                  prevPage: result.pagination.prevCursor
                    ? `paginated://cursor/${result.pagination.prevCursor}?size=${size}&sortBy=${sortBy}&sortOrder=${sortOrder}`
                    : null,
                  firstPage: `paginated://cursor/null?size=${size}&sortBy=${sortBy}&sortOrder=${sortOrder}`,
                  differentSort: `paginated://cursor/null?size=${size}&sortBy=createdAt&sortOrder=desc`
                }
              }
            }, null, 2)
          }]
        };
      } catch (error) {
        logger.error('Cursor pagination failed', error as Error);
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Cursor pagination failed',
              message: (error as Error).message
            }, null, 2)
          }]
        };
      }
    }
  );

  // Filtered paginated resource
  server.registerResource(
    'paginated-filtered',
    new ResourceTemplate('paginated://filtered/{category?}?page={page?}&size={size?}&status={status?}', { 
      list: undefined 
    }),
    {
      title: 'Filtered Paginated Data',
      description: 'Demonstrates pagination with filtering and search capabilities',
      mimeType: 'application/json'
    },
    async (uri) => {
      const url = new URL(uri.href);
      const category = url.pathname.split('/')[2] || '';
      const page = parseInt(url.searchParams.get('page') || '1', 10);
      const size = parseInt(url.searchParams.get('size') || '10', 10);
      const status = url.searchParams.get('status');
      
      // Apply filters
      let filteredData = sampleData;
      
      if (category && category !== 'all') {
        filteredData = filteredData.filter(item => item.category === category);
      }
      
      if (status) {
        filteredData = filteredData.filter(item => item.status === status);
      }
      
      const paginationOptions = { page, size };
      const validation = validatePaginationOptions(paginationOptions);
      
      if (!validation.isValid) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Invalid pagination parameters',
              details: validation.errors
            }, null, 2)
          }]
        };
      }
      
      const result = paginate(filteredData, paginationOptions);
      const meta = createResourcePaginationMeta(filteredData.length, page, size);
      
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            ...result,
            metadata: {
              ...meta,
              paginationType: 'filtered-offset',
              filters: {
                category: category || 'all',
                status: status || 'all'
              },
              totalItems: sampleData.length,
              filteredItems: filteredData.length,
              availableCategories: ['technology', 'science', 'business', 'health', 'entertainment'],
              availableStatuses: ['active', 'inactive', 'pending'],
              examples: {
                nextPage: page < meta.pages 
                  ? `paginated://filtered/${category}?page=${page + 1}&size=${size}${status ? `&status=${status}` : ''}` 
                  : null,
                prevPage: page > 1 
                  ? `paginated://filtered/${category}?page=${page - 1}&size=${size}${status ? `&status=${status}` : ''}` 
                  : null,
                differentFilter: 'paginated://filtered/technology?page=1&size=10&status=active',
                allCategories: 'paginated://filtered/all?page=1&size=10'
              }
            }
          }, null, 2)
        }]
      };
    }
  );

  // Async pagination simulation resource
  server.registerResource(
    'paginated-async',
    new ResourceTemplate('paginated://async/{cursor?}?size={size?}&delay={delay?}', { 
      list: undefined 
    }),
    {
      title: 'Async Paginated Data',
      description: 'Demonstrates async cursor pagination with simulated database queries',
      mimeType: 'application/json'
    },
    async (uri) => {
      const url = new URL(uri.href);
      const cursor = url.pathname.split('/')[2] === 'null' ? undefined : url.pathname.split('/')[2];
      const size = parseInt(url.searchParams.get('size') || '5', 10);
      const delay = parseInt(url.searchParams.get('delay') || '100', 10); // Simulated delay
      
      const paginationOptions = { cursor, size };
      const validation = validatePaginationOptions(paginationOptions);
      
      if (!validation.isValid) {
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Invalid pagination parameters',
              details: validation.errors
            }, null, 2)
          }]
        };
      }
      
      // Simulate async database fetch
      const simulatedFetch = async (fetchCursor?: string, fetchSize?: number): Promise<CursorPaginationItem[]> => {
        // Add artificial delay to simulate database query
        await new Promise(resolve => setTimeout(resolve, delay));
        
        let startIndex = 0;
        if (fetchCursor) {
          try {
            const cursorData = JSON.parse(Buffer.from(fetchCursor, 'base64').toString());
            const cursorId = cursorData.value;
            startIndex = sampleData.findIndex(item => item.id > cursorId);
            if (startIndex === -1) startIndex = sampleData.length;
          } catch {
            startIndex = 0;
          }
        }
        
        return sampleData.slice(startIndex, startIndex + (fetchSize || 5));
      };
      
      try {
        const startTime = Date.now();
        const result = await paginateAsync(simulatedFetch, paginationOptions);
        const endTime = Date.now();
        
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              ...result,
              metadata: {
                paginationType: 'async-cursor',
                queryTime: `${endTime - startTime}ms`,
                simulatedDelay: `${delay}ms`,
                requestedSize: size,
                totalItems: sampleData.length,
                examples: {
                  nextPage: result.pagination.nextCursor
                    ? `paginated://async/${result.pagination.nextCursor}?size=${size}&delay=${delay}`
                    : null,
                  firstPage: `paginated://async/null?size=${size}&delay=${delay}`,
                  fasterQuery: `paginated://async/null?size=${size}&delay=50`,
                  largerPage: `paginated://async/null?size=20&delay=${delay}`
                }
              }
            }, null, 2)
          }]
        };
      } catch (error) {
        logger.error('Async pagination failed', error as Error);
        return {
          contents: [{
            uri: uri.href,
            text: JSON.stringify({
              error: 'Async pagination failed',
              message: (error as Error).message
            }, null, 2)
          }]
        };
      }
    }
  );

  // Pagination documentation resource
  server.registerResource(
    'pagination-docs',
    'docs://pagination',
    {
      title: 'Pagination Documentation',
      description: 'Complete guide to using pagination features in this MCP server',
      mimeType: 'text/markdown'
    },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: `# Pagination Documentation

## Overview

This MCP server provides comprehensive pagination support for handling large datasets efficiently. We support both traditional offset-based pagination and modern cursor-based pagination patterns.

## Pagination Types

### 1. Offset-based Pagination (Traditional)

**Best for:** Known dataset sizes, simple navigation, user interfaces with page numbers

**Resource:** \`paginated://offset/{page?}/{size?}\`

**Parameters:**
- \`page\`: Page number (1-based, default: 1)  
- \`size\`: Items per page (default: 10, max: 1000)

**Example:**
\`\`\`
paginated://offset/1/10     # First page, 10 items
paginated://offset/3/25     # Third page, 25 items
\`\`\`

### 2. Cursor-based Pagination

**Best for:** Large datasets, real-time data, better performance with frequent updates

**Resource:** \`paginated://cursor/{cursor?}?size={size?}&sortBy={sortBy?}&sortOrder={sortOrder?}\`

**Parameters:**
- \`cursor\`: Base64 encoded position marker (optional for first page)
- \`size\`: Items per page (default: 10, max: 1000)
- \`sortBy\`: Sort field (default: 'id')
- \`sortOrder\`: 'asc' or 'desc' (default: 'asc')

**Example:**
\`\`\`
paginated://cursor/null?size=10&sortBy=createdAt&sortOrder=desc
paginated://cursor/eyJ2YWx1ZSI6Iml0ZW0tMDEwIiwiZGlyZWN0aW9uIjoibmV4dCJ9?size=10
\`\`\`

### 3. Filtered Pagination

**Best for:** Search results, category filtering, complex queries

**Resource:** \`paginated://filtered/{category?}?page={page?}&size={size?}&status={status?}\`

**Parameters:**
- \`category\`: Filter by category
- \`status\`: Filter by status
- \`page\`: Page number
- \`size\`: Items per page

**Example:**
\`\`\`
paginated://filtered/technology?page=1&size=20&status=active
\`\`\`

### 4. Async Pagination

**Best for:** Database queries, API calls, simulating real-world data fetching

**Resource:** \`paginated://async/{cursor?}?size={size?}&delay={delay?}\`

**Parameters:**
- \`cursor\`: Cursor for next page
- \`size\`: Items per page
- \`delay\`: Simulated query delay in milliseconds

## Response Format

All paginated responses include:

\`\`\`json
{
  "data": [...],           // Array of items for current page
  "pagination": {
    "size": 10,           // Requested page size
    "hasNext": true,      // Whether there are more pages
    "hasPrev": false,     // Whether there are previous pages
    
    // Offset pagination fields
    "page": 1,            // Current page number
    "total": 150,         // Total number of items
    
    // Cursor pagination fields  
    "nextCursor": "...",  // Cursor for next page
    "prevCursor": "..."   // Cursor for previous page
  },
  "metadata": {
    "paginationType": "offset|cursor|filtered|async",
    "totalItems": 150,
    "examples": {...}     // Example URLs for navigation
  }
}
\`\`\`

## Best Practices

### When to Use Each Type

1. **Offset Pagination**: 
   - Small to medium datasets (< 10,000 items)
   - User needs page numbers
   - Data doesn't change frequently

2. **Cursor Pagination**:
   - Large datasets (> 10,000 items)  
   - Real-time data with frequent updates
   - Better performance for deep pagination

3. **Filtered Pagination**:
   - Search functionality
   - Complex filtering requirements
   - Category-based browsing

4. **Async Pagination**:
   - Database-backed resources
   - API-backed resources
   - When you need to simulate query time

### Performance Considerations

- **Offset pagination**: Performance degrades with higher page numbers
- **Cursor pagination**: Consistent performance regardless of position
- **Filtering**: Consider indexing filtered fields
- **Caching**: Cache results when possible for repeated queries

### Error Handling

- Invalid page numbers default to page 1
- Invalid cursors start from the beginning
- Size limits are enforced (max 1000)
- Validation errors return detailed error messages

## Implementation Notes

The pagination utilities are implemented in \`src/utils/pagination.ts\` and provide:

- \`paginate()\`: Basic offset pagination
- \`paginateWithCursor()\`: Cursor-based pagination  
- \`paginateAsync()\`: Async cursor pagination
- \`validatePaginationOptions()\`: Input validation
- \`createResourcePaginationMeta()\`: Metadata helpers

These utilities handle edge cases, performance optimization, and provide consistent interfaces across all pagination types.
`
      }]
    })
  );
}