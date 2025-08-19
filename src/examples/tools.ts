import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { logger } from '../utils/logger.js';
import * as fs from 'fs';
import * as path from 'path';

export function setupExampleTools(server: McpServer): void {
  logger.info('Setting up example tools');
  
  // Calculator Tools with Comprehensive Validation
  server.tool(
    'calculator',
    'Perform basic arithmetic operations with validation',
    {
      operation: {
        type: 'string',
        description: 'Operation to perform: add, subtract, multiply, divide, power, sqrt, or factorial'
      },
      a: {
        type: 'number',
        description: 'First number'
      },
      b: {
        type: 'number',
        description: 'Second number (optional for sqrt and factorial)'
      }
    },
    async ({ operation, a, b }) => {
      try {
        logger.info('Calculator operation requested', { operation, a, b });

        // Validate inputs
        if (typeof a !== 'number' || isNaN(a)) {
          return {
            content: [{
              type: 'text',
              text: 'Error: First number (a) must be a valid number'
            }]
          };
        }

        let result: number;
        
        switch (operation) {
          case 'add':
            if (typeof b !== 'number' || isNaN(b)) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Addition requires both numbers (a and b)'
                }]
              };
            }
            result = a + b;
            break;
            
          case 'subtract':
            if (typeof b !== 'number' || isNaN(b)) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Subtraction requires both numbers (a and b)'
                }]
              };
            }
            result = a - b;
            break;
            
          case 'multiply':
            if (typeof b !== 'number' || isNaN(b)) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Multiplication requires both numbers (a and b)'
                }]
              };
            }
            result = a * b;
            break;
            
          case 'divide':
            if (typeof b !== 'number' || isNaN(b)) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Division requires both numbers (a and b)'
                }]
              };
            }
            if (b === 0) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Division by zero is not allowed'
                }]
              };
            }
            result = a / b;
            break;
            
          case 'power':
            if (typeof b !== 'number' || isNaN(b)) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Power operation requires both numbers (a and b)'
                }]
              };
            }
            result = Math.pow(a, b);
            break;
            
          case 'sqrt':
            if (a < 0) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Cannot calculate square root of negative number'
                }]
              };
            }
            result = Math.sqrt(a);
            break;
            
          case 'factorial':
            if (a < 0 || !Number.isInteger(a)) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Factorial is only defined for non-negative integers'
                }]
              };
            }
            if (a > 170) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Factorial too large (maximum: 170!)'
                }]
              };
            }
            result = 1;
            for (let i = 2; i <= a; i++) {
              result *= i;
            }
            break;
            
          default:
            return {
              content: [{
                type: 'text',
                text: `Error: Unknown operation '${operation}'. Supported: add, subtract, multiply, divide, power, sqrt, factorial`
              }]
            };
        }

        // Check for overflow or invalid results
        if (!isFinite(result)) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Result is infinite or not a number'
            }]
          };
        }

        logger.info('Calculator operation completed', { operation, a, b, result });
        
        return {
          content: [{
            type: 'text',
            text: `Result: ${result}`
          }]
        };
        
      } catch (error) {
        logger.error('Calculator operation failed', error);
        return {
          content: [{
            type: 'text',
            text: `Error: ${error instanceof Error ? error.message : 'Unknown calculation error'}`
          }]
        };
      }
    }
  );

  // File Operations Tool
  server.tool(
    'file-operations',
    'Perform safe file operations with comprehensive validation',
    {
      operation: {
        type: 'string',
        description: 'Operation: read, write, append, exists, delete, list, or create-dir'
      },
      filepath: {
        type: 'string',
        description: 'File or directory path (relative paths will be resolved from current directory)'
      },
      content: {
        type: 'string',
        description: 'Content for write/append operations'
      }
    },
    async ({ operation, filepath, content }) => {
      try {
        logger.info('File operation requested', { operation, filepath });

        // Security validation - prevent dangerous paths
        if (filepath.includes('..') || filepath.startsWith('/') || filepath.includes('\\..\\')) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Path traversal not allowed for security reasons'
            }]
          };
        }

        // Resolve relative path safely
        const safePath = path.resolve(process.cwd(), filepath);
        
        // Ensure the resolved path is within current directory
        if (!safePath.startsWith(process.cwd())) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Access outside current directory not allowed'
            }]
          };
        }

        switch (operation) {
          case 'read':
            try {
              const fileContent = fs.readFileSync(safePath, 'utf-8');
              logger.info('File read successfully', { filepath: safePath, size: fileContent.length });
              return {
                content: [{
                  type: 'text',
                  text: `File content (${fileContent.length} characters):\n\n${fileContent}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error reading file: ${error instanceof Error ? error.message : 'Unknown error'}`
                }]
              };
            }
            
          case 'write':
            if (typeof content !== 'string') {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Content is required for write operation'
                }]
              };
            }
            try {
              fs.writeFileSync(safePath, content, 'utf-8');
              logger.info('File written successfully', { filepath: safePath, size: content.length });
              return {
                content: [{
                  type: 'text',
                  text: `File written successfully (${content.length} characters)`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error writing file: ${error instanceof Error ? error.message : 'Unknown error'}`
                }]
              };
            }
            
          case 'append':
            if (typeof content !== 'string') {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Content is required for append operation'
                }]
              };
            }
            try {
              fs.appendFileSync(safePath, content, 'utf-8');
              logger.info('File appended successfully', { filepath: safePath, appendSize: content.length });
              return {
                content: [{
                  type: 'text',
                  text: `Content appended successfully (${content.length} characters)`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error appending to file: ${error instanceof Error ? error.message : 'Unknown error'}`
                }]
              };
            }
            
          case 'exists':
            const exists = fs.existsSync(safePath);
            return {
              content: [{
                type: 'text',
                text: `Path exists: ${exists}`
              }]
            };
            
          case 'delete':
            try {
              if (fs.existsSync(safePath)) {
                const stats = fs.statSync(safePath);
                if (stats.isDirectory()) {
                  fs.rmSync(safePath, { recursive: true, force: true });
                  logger.info('Directory deleted successfully', { filepath: safePath });
                  return {
                    content: [{
                      type: 'text',
                      text: 'Directory deleted successfully'
                    }]
                  };
                } else {
                  fs.unlinkSync(safePath);
                  logger.info('File deleted successfully', { filepath: safePath });
                  return {
                    content: [{
                      type: 'text',
                      text: 'File deleted successfully'
                    }]
                  };
                }
              } else {
                return {
                  content: [{
                    type: 'text',
                    text: 'Error: Path does not exist'
                  }]
                };
              }
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error deleting: ${error instanceof Error ? error.message : 'Unknown error'}`
                }]
              };
            }
            
          case 'list':
            try {
              const items = fs.readdirSync(safePath, { withFileTypes: true });
              const listing = items.map(item => {
                const type = item.isDirectory() ? 'DIR' : 'FILE';
                const stats = fs.statSync(path.join(safePath, item.name));
                const size = item.isFile() ? stats.size : 0;
                const modified = stats.mtime.toISOString();
                return `${type.padEnd(4)} ${item.name.padEnd(30)} ${size.toString().padStart(10)} ${modified}`;
              });
              
              return {
                content: [{
                  type: 'text',
                  text: `Directory listing for ${safePath}:\n\nType Name${' '.repeat(26)} Size       Modified\n${'-'.repeat(75)}\n${listing.join('\n')}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error listing directory: ${error instanceof Error ? error.message : 'Unknown error'}`
                }]
              };
            }
            
          case 'create-dir':
            try {
              fs.mkdirSync(safePath, { recursive: true });
              logger.info('Directory created successfully', { filepath: safePath });
              return {
                content: [{
                  type: 'text',
                  text: 'Directory created successfully'
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error creating directory: ${error instanceof Error ? error.message : 'Unknown error'}`
                }]
              };
            }
            
          default:
            return {
              content: [{
                type: 'text',
                text: `Error: Unknown operation '${operation}'. Supported: read, write, append, exists, delete, list, create-dir`
              }]
            };
        }
        
      } catch (error) {
        logger.error('File operation failed', error);
        return {
          content: [{
            type: 'text',
            text: `Error: ${error instanceof Error ? error.message : 'Unknown file operation error'}`
          }]
        };
      }
    }
  );

  // HTTP API Call Tool  
  server.tool(
    'http-request',
    'Make HTTP requests with comprehensive validation and error handling',
    {
      url: {
        type: 'string',
        description: 'URL to make request to (must be http or https)'
      },
      method: {
        type: 'string',
        description: 'HTTP method: GET, POST, PUT, DELETE, PATCH'
      },
      headers: {
        type: 'string',
        description: 'JSON string of headers (optional)'
      },
      body: {
        type: 'string',
        description: 'Request body for POST/PUT/PATCH requests (optional)'
      },
      timeout: {
        type: 'number',
        description: 'Request timeout in milliseconds (default: 10000, max: 30000)'
      }
    },
    async ({ url, method = 'GET', headers, body, timeout = 10000 }) => {
      try {
        logger.info('HTTP request initiated', { url, method, timeout });

        // Validate URL
        let parsedUrl: URL;
        try {
          parsedUrl = new URL(url);
        } catch (error) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Invalid URL format'
            }]
          };
        }

        // Security validation - only allow http/https
        if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Only HTTP and HTTPS protocols are allowed'
            }]
          };
        }

        // Validate method
        const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
        const upperMethod = method.toUpperCase();
        if (!validMethods.includes(upperMethod)) {
          return {
            content: [{
              type: 'text',
              text: `Error: Invalid HTTP method. Allowed: ${validMethods.join(', ')}`
            }]
          };
        }

        // Validate timeout
        if (typeof timeout !== 'number' || timeout < 1000 || timeout > 30000) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Timeout must be between 1000 and 30000 milliseconds'
            }]
          };
        }

        // Parse headers if provided
        let parsedHeaders: Record<string, string> = {};
        if (headers) {
          try {
            parsedHeaders = JSON.parse(headers);
            if (typeof parsedHeaders !== 'object' || parsedHeaders === null) {
              return {
                content: [{
                  type: 'text',
                  text: 'Error: Headers must be a JSON object'
                }]
              };
            }
          } catch (error) {
            return {
              content: [{
              type: 'text',
              text: 'Error: Invalid JSON format for headers'
            }]
          };
          }
        }

        // Set default headers
        const finalHeaders: Record<string, string> = {
          'User-Agent': 'MCP-Server-Template/1.0.0',
          'Accept': 'application/json, text/plain, */*',
          ...parsedHeaders
        };

        // For requests with body, set content-type if not provided
        if (body && ['POST', 'PUT', 'PATCH'].includes(upperMethod)) {
          if (!finalHeaders['Content-Type'] && !finalHeaders['content-type']) {
            finalHeaders['Content-Type'] = 'application/json';
          }
        }

        // Make the HTTP request
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), timeout);

          const response = await fetch(url, {
            method: upperMethod,
            headers: finalHeaders,
            body: body && ['POST', 'PUT', 'PATCH'].includes(upperMethod) ? body : undefined,
            signal: controller.signal
          });

          clearTimeout(timeoutId);

          // Get response text
          const responseText = await response.text();
          
          // Try to parse as JSON, fallback to text
          let responseData: any;
          try {
            responseData = JSON.parse(responseText);
          } catch {
            responseData = responseText;
          }

          const result = {
            status: response.status,
            statusText: response.statusText,
            headers: Object.fromEntries(response.headers.entries()),
            data: responseData,
            url: response.url,
            ok: response.ok
          };

          logger.info('HTTP request completed', { url, method, status: response.status });

          return {
            content: [{
              type: 'text',
              text: `HTTP ${upperMethod} ${url}\n\nStatus: ${response.status} ${response.statusText}\nOK: ${response.ok}\n\nResponse Headers:\n${JSON.stringify(result.headers, null, 2)}\n\nResponse Body:\n${typeof responseData === 'object' ? JSON.stringify(responseData, null, 2) : responseData}`
            }]
          };

        } catch (error) {
          if (error instanceof Error) {
            if (error.name === 'AbortError') {
              return {
                content: [{
                  type: 'text',
                  text: `Error: Request timeout after ${timeout}ms`
                }]
              };
            }
            return {
              content: [{
                type: 'text',
                text: `Error: ${error.message}`
              }]
            };
          }
          return {
            content: [{
              type: 'text',
              text: 'Error: Unknown network error'
            }]
          };
        }

      } catch (error) {
        logger.error('HTTP request failed', error);
        return {
          content: [{
            type: 'text',
            text: `Error: ${error instanceof Error ? error.message : 'Unknown HTTP request error'}`
          }]
        };
      }
    }
  );

  // Data Processing Tool
  server.tool(
    'data-processor',
    'Process and analyze data with various operations',
    {
      operation: {
        type: 'string',
        description: 'Operation: parse-json, parse-csv, format-json, validate-json, sort-array, filter-array, or statistics'
      },
      data: {
        type: 'string',
        description: 'Input data to process'
      },
      options: {
        type: 'string',
        description: 'JSON string of operation-specific options'
      }
    },
    async ({ operation, data, options }) => {
      try {
        logger.info('Data processing requested', { operation, dataLength: data?.length });

        if (!data) {
          return {
            content: [{
              type: 'text',
              text: 'Error: Data is required for processing'
            }]
          };
        }

        // Parse options if provided
        let parsedOptions: any = {};
        if (options) {
          try {
            parsedOptions = JSON.parse(options);
          } catch (error) {
            return {
              content: [{
                type: 'text',
                text: 'Error: Invalid JSON format for options'
              }]
            };
          }
        }

        switch (operation) {
          case 'parse-json':
            try {
              const parsed = JSON.parse(data);
              return {
                content: [{
                  type: 'text',
                  text: `JSON parsed successfully:\n\n${JSON.stringify(parsed, null, 2)}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error parsing JSON: ${error instanceof Error ? error.message : 'Invalid JSON'}`
                }]
              };
            }

          case 'parse-csv':
            try {
              const lines = data.trim().split('\n');
              const headers = lines[0].split(',').map((h: string) => h.trim());
              const rows = lines.slice(1).map((line: string) => {
                const values = line.split(',').map((v: string) => v.trim());
                const row: Record<string, string> = {};
                headers.forEach((header: string, index: number) => {
                  row[header] = values[index] || '';
                });
                return row;
              });

              return {
                content: [{
                  type: 'text',
                  text: `CSV parsed successfully (${rows.length} rows, ${headers.length} columns):\n\nHeaders: ${headers.join(', ')}\n\nData:\n${JSON.stringify(rows, null, 2)}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error parsing CSV: ${error instanceof Error ? error.message : 'Invalid CSV format'}`
                }]
              };
            }

          case 'format-json':
            try {
              const parsed = JSON.parse(data);
              const indentation = parsedOptions.indent || 2;
              const formatted = JSON.stringify(parsed, null, indentation);
              return {
                content: [{
                  type: 'text',
                  text: `JSON formatted:\n\n${formatted}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error formatting JSON: ${error instanceof Error ? error.message : 'Invalid JSON'}`
                }]
              };
            }

          case 'validate-json':
            try {
              JSON.parse(data);
              return {
                content: [{
                  type: 'text',
                  text: '✅ JSON is valid'
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `❌ JSON is invalid: ${error instanceof Error ? error.message : 'Parse error'}`
                }]
              };
            }

          case 'sort-array':
            try {
              const array = JSON.parse(data);
              if (!Array.isArray(array)) {
                return {
                  content: [{
                    type: 'text',
                    text: 'Error: Data must be a JSON array for sorting'
                  }]
                };
              }

              const sortField = parsedOptions.field;
              const sortOrder = parsedOptions.order || 'asc';

              let sorted;
              if (sortField) {
                sorted = array.sort((a, b) => {
                  const aVal = a[sortField];
                  const bVal = b[sortField];
                  if (sortOrder === 'desc') {
                    return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
                  }
                  return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                });
              } else {
                sorted = array.sort((a, b) => {
                  if (sortOrder === 'desc') {
                    return a < b ? 1 : a > b ? -1 : 0;
                  }
                  return a > b ? 1 : a < b ? -1 : 0;
                });
              }

              return {
                content: [{
                  type: 'text',
                  text: `Array sorted (${sortOrder} order${sortField ? ` by ${sortField}` : ''}):\n\n${JSON.stringify(sorted, null, 2)}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error sorting array: ${error instanceof Error ? error.message : 'Invalid array data'}`
                }]
              };
            }

          case 'filter-array':
            try {
              const array = JSON.parse(data);
              if (!Array.isArray(array)) {
                return {
                  content: [{
                    type: 'text',
                    text: 'Error: Data must be a JSON array for filtering'
                  }]
                };
              }

              const filterField = parsedOptions.field;
              const filterValue = parsedOptions.value;
              const filterOperator = parsedOptions.operator || 'equals';

              if (!filterField || filterValue === undefined) {
                return {
                  content: [{
                    type: 'text',
                    text: 'Error: Filter requires field and value in options: {"field": "name", "value": "test", "operator": "equals"}'
                  }]
                };
              }

              const filtered = array.filter(item => {
                const itemValue = item[filterField];
                switch (filterOperator) {
                  case 'equals':
                    return itemValue === filterValue;
                  case 'contains':
                    return String(itemValue).includes(String(filterValue));
                  case 'greater':
                    return Number(itemValue) > Number(filterValue);
                  case 'less':
                    return Number(itemValue) < Number(filterValue);
                  default:
                    return itemValue === filterValue;
                }
              });

              return {
                content: [{
                  type: 'text',
                  text: `Array filtered (${filtered.length}/${array.length} items match):\n\n${JSON.stringify(filtered, null, 2)}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error filtering array: ${error instanceof Error ? error.message : 'Invalid array data'}`
                }]
              };
            }

          case 'statistics':
            try {
              const array = JSON.parse(data);
              if (!Array.isArray(array)) {
                return {
                  content: [{
                    type: 'text',
                    text: 'Error: Data must be a JSON array for statistics'
                  }]
                };
              }

              const field = parsedOptions.field;
              let numbers: number[];

              if (field) {
                numbers = array.map(item => Number(item[field])).filter(n => !isNaN(n));
              } else {
                numbers = array.map(item => Number(item)).filter(n => !isNaN(n));
              }

              if (numbers.length === 0) {
                return {
                  content: [{
                    type: 'text',
                    text: 'Error: No valid numbers found for statistics'
                  }]
                };
              }

              const sum = numbers.reduce((a, b) => a + b, 0);
              const mean = sum / numbers.length;
              const min = Math.min(...numbers);
              const max = Math.max(...numbers);
              const sorted = [...numbers].sort((a, b) => a - b);
              const median = sorted.length % 2 === 0 
                ? ((sorted[sorted.length / 2 - 1] || 0) + (sorted[sorted.length / 2] || 0)) / 2
                : sorted[Math.floor(sorted.length / 2)] || 0;

              const variance = numbers.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / numbers.length;
              const stdDev = Math.sqrt(variance);

              return {
                content: [{
                  type: 'text',
                  text: `Statistics${field ? ` for field "${field}"` : ''}:\n\nCount: ${numbers.length}\nSum: ${sum}\nMean: ${mean.toFixed(2)}\nMedian: ${median}\nMin: ${min}\nMax: ${max}\nStandard Deviation: ${stdDev.toFixed(2)}\nVariance: ${variance.toFixed(2)}`
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: `Error calculating statistics: ${error instanceof Error ? error.message : 'Invalid data'}`
                }]
              };
            }

          default:
            return {
              content: [{
                type: 'text',
                text: `Error: Unknown operation '${operation}'. Supported: parse-json, parse-csv, format-json, validate-json, sort-array, filter-array, statistics`
              }]
            };
        }

      } catch (error) {
        logger.error('Data processing failed', error);
        return {
          content: [{
            type: 'text',
            text: `Error: ${error instanceof Error ? error.message : 'Unknown data processing error'}`
          }]
        };
      }
    }
  );

  logger.info('Example tools setup completed - 4 comprehensive tools registered');
}