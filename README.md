# MCP Server Template

A comprehensive Model Context Protocol (MCP) server template with modern features and best practices. This template provides a solid foundation for building production-ready MCP servers with support for multiple transport protocols, authentication, and all the latest MCP utilities.

## 🚀 Features

### ✅ **Implemented**

#### **Core Server**
- 🔧 **MCP SDK Integration** - Latest `@modelcontextprotocol/sdk` with TypeScript support
- 📦 **Modular Architecture** - Clean separation of concerns with dedicated modules
- 🔄 **Lifecycle Management** - Proper initialization, shutdown, and error handling
- 📊 **Comprehensive Logging** - Structured logging with Winston and context tracking
- ⚙️ **Configuration Management** - Environment-based configuration with validation

#### **Transport Protocols**
- 📡 **Stdio Transport** - Standard input/output for CLI and direct integrations
- 🌐 **HTTP Transport** - Modern streamable HTTP with Express.js
- 🔄 **Backwards Compatibility** - Legacy SSE transport support
- 🛡️ **CORS Support** - Configurable cross-origin resource sharing
- 📋 **Session Management** - Stateful sessions with proper cleanup
- 🔒 **Security Middleware** - Helmet for security headers, rate limiting
- 📝 **Request Logging** - Context-aware HTTP request/response logging

#### **Utilities & Infrastructure**
- ❌ **Cancellation Tokens** - Graceful operation cancellation
- 📈 **Progress Tracking** - Real-time progress monitoring for long operations
- 📄 **Pagination Support** - Cursor and offset-based pagination utilities
- 🔧 **Type Safety** - Comprehensive TypeScript types and interfaces
- 🏗️ **Build System** - Modern ESM build with TypeScript compilation
- 📋 **Code Quality** - ESLint configuration with TypeScript rules

### 🚧 **In Progress / Planned**

#### **Authentication & Authorization**
- 🔐 **OAuth 2.0 Support** - Complete OAuth 2.0 authorization server
- 🎫 **JWT Token Management** - Secure token validation and refresh
- 🔑 **Scope Management** - Fine-grained permission control

#### **MCP Examples & Capabilities**
- 📚 **Example Resources** - Static, dynamic, file system, and API resources
- 🛠️ **Example Tools** - Calculator, file ops, API calls with validation
- 💬 **Example Prompts** - Data analysis, code generation, content creation
- 🤖 **Sampling Support** - Server-initiated LLM interactions and agentic behaviors

#### **Advanced Features**
- 📡 **Ping/Heartbeat** - Connection health monitoring
- 📊 **Advanced Progress** - Multi-stage progress with real-time updates
- 📄 **Advanced Pagination** - Large dataset handling with cursors
- 📝 **Comprehensive Documentation** - Usage guides and API documentation

## 📋 Requirements

- **Node.js** >= 18.0.0
- **TypeScript** >= 5.0.0
- **npm** or **yarn** for package management

## 🛠️ Installation

```bash
# Clone the template
git clone <your-repo-url>
cd mcp-server-template

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
# nano .env
```

## ⚙️ Configuration

### Environment Variables

The server uses environment variables for configuration. Copy `.env.example` to `.env` and customize:

```bash
# MCP Server Configuration
SERVER_NAME=mcp-server-template
SERVER_VERSION=1.0.0
NODE_ENV=development

# HTTP Server Configuration
HTTP_PORT=3000
HTTP_HOST=localhost

# Session Configuration
SESSION_SECRET=your-session-secret-change-this-in-production

# OAuth 2.0 Configuration (Planned)
OAUTH_CLIENT_ID=your-oauth-client-id
OAUTH_CLIENT_SECRET=your-oauth-client-secret
OAUTH_REDIRECT_URI=http://localhost:3000/auth/callback

# CORS Configuration
CORS_ORIGIN=http://localhost:3000
CORS_CREDENTIALS=true

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

## 🚀 Usage

### Development

```bash
# Build the project
npm run build

# Start in development mode (with auto-reload)
npm run dev

# Start stdio server
npm run start:stdio

# Start HTTP server
npm run start:http
```

### Production

```bash
# Build for production
npm run build

# Start stdio server
npm start

# Or start HTTP server
node dist/http-server.js
```

### Claude Desktop Integration

To use this server with Claude Desktop, add it to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-server-template": {
      "command": "node",
      "args": ["/path/to/your/project/dist/stdio-server.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

**Claude Desktop Config Locations:**
- **macOS**: `~/Library/Application\ Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### MCP Client Integration

For programmatic integration with other MCP clients:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "child_process";

// Connect to stdio server
const serverProcess = spawn("node", ["dist/stdio-server.js"]);
const transport = new StdioClientTransport({
  spawn: () => serverProcess
});

const client = new Client({
  name: "example-client",
  version: "1.0.0"
});

await client.connect(transport);

// List available resources
const resources = await client.request(
  { method: "resources/list" },
  { resourceListRequest: {} }
);

console.log("Available resources:", resources);
```

### HTTP Client Examples

For HTTP transport integration:

```bash
# Health check
curl http://localhost:3000/health

# Connect to MCP over HTTP (requires proper headers)
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'
```

### Testing the Server

```bash
# Build first
npm run build

# Test stdio transport
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' | node dist/stdio-server.js

# Test HTTP server (in separate terminal)
npm run start:http
curl http://localhost:3000/health
```

## 📡 Transport Protocols

### 1. Stdio Transport

For command-line tools and direct integrations:

```bash
# Run the stdio server
npm run start:stdio

# Or use the built version
node dist/stdio-server.js
```

**Use Cases:**
- Claude Desktop integration
- Command-line tools
- Direct process communication

### 2. HTTP Transport

For web applications and remote integrations:

```bash
# Start HTTP server
npm run start:http

# Server will be available at:
# http://localhost:3000
```

**Endpoints:**
- `GET /health` - Health check endpoint
- `POST /mcp` - Modern streamable HTTP transport
- `GET /sse` - Legacy SSE transport (backwards compatibility)
- `POST /messages` - Legacy message endpoint for SSE
- `DELETE /session/:sessionId` - Session termination
- `GET /progress/:progressId` - Progress tracking (planned)

**Features:**
- ✅ CORS support with configurable origins
- ✅ Session management with secure cookies
- ✅ Rate limiting protection
- ✅ Security headers via Helmet
- ✅ Request/response logging
- ✅ Backwards compatibility with SSE

## 🚀 Deployment

### Docker Deployment (Coming Soon)

The template will include Docker support for easy deployment:

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
COPY .env.production ./.env

EXPOSE 3000
CMD ["node", "dist/http-server.js"]
```

### Process Management

For production deployments, use a process manager like PM2:

```bash
# Install PM2 globally
npm install -g pm2

# Create PM2 ecosystem file
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'mcp-server-template-http',
    script: 'dist/http-server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      HTTP_PORT: 3000
    }
  }, {
    name: 'mcp-server-template-stdio',
    script: 'dist/stdio-server.js',
    instances: 1,
    exec_mode: 'fork',
    env: {
      NODE_ENV: 'production'
    }
  }]
}
EOF

# Start with PM2
pm2 start ecosystem.config.js
```

### Systemd Service

For Linux deployments with systemd:

```ini
# /etc/systemd/system/mcp-server-template.service
[Unit]
Description=MCP Server Template
After=network.target

[Service]
Type=simple
User=mcp-user
WorkingDirectory=/opt/mcp-server-template
ExecStart=/usr/bin/node dist/http-server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=HTTP_PORT=3000
EnvironmentFile=/opt/mcp-server-template/.env

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start the service
sudo systemctl enable mcp-server-template
sudo systemctl start mcp-server-template
sudo systemctl status mcp-server-template
```

### Environment-specific Configuration

Create environment-specific configuration files:

```bash
# Development
cp .env.example .env.development

# Production
cp .env.example .env.production
```

Update your package.json scripts for environment-specific builds:

```json
{
  "scripts": {
    "start:dev": "NODE_ENV=development node dist/http-server.js",
    "start:prod": "NODE_ENV=production node dist/http-server.js"
  }
}
```

### Reverse Proxy Configuration

Example nginx configuration for HTTP transport:

```nginx
server {
    listen 80;
    server_name your-mcp-server.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Support for streaming responses
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

## 🏗️ Architecture

### Project Structure

```
src/
├── server.ts              # Main MCP server class
├── index.ts               # Public API exports
├── stdio-server.ts        # Stdio transport entry point
├── http-server.ts         # HTTP transport entry point
├── types/
│   └── index.ts           # TypeScript type definitions
├── utils/
│   ├── config.ts          # Configuration management
│   ├── logger.ts          # Logging utilities
│   ├── cancellation.ts    # Cancellation token implementation
│   ├── progress.ts        # Progress tracking utilities
│   └── pagination.ts     # Pagination utilities
├── transports/
│   └── http.ts           # HTTP transport implementation
├── examples/              # Example implementations (planned)
│   ├── resources.ts      # Example resources
│   ├── tools.ts          # Example tools
│   ├── prompts.ts        # Example prompts
│   └── sampling.ts       # Sampling capabilities
└── auth/                 # Authentication (planned)
    └── oauth.ts          # OAuth 2.0 implementation
```

### Core Components

#### MCPServerTemplate
The main server class that orchestrates all MCP functionality:
- Manages server lifecycle
- Coordinates transport connections
- Sets up example capabilities
- Handles graceful shutdown

#### Transport Layer
- **StdioServerTransport** - Standard I/O communication
- **HTTPTransportManager** - HTTP server with Express.js
- **StreamableHTTPServerTransport** - Modern HTTP transport
- **SSEServerTransport** - Legacy SSE support

#### Utilities
- **CancellationToken** - Cooperative cancellation
- **ProgressTracker** - Operation progress monitoring
- **Logger** - Structured logging with context
- **Configuration** - Environment-based settings

## 🔧 Development

### Scripts

```bash
# Development
npm run dev          # Start with auto-reload
npm run build        # Compile TypeScript
npm run clean        # Clean build directory

# Quality
npm run lint         # Run ESLint
npm run lint:fix     # Fix ESLint issues
npm run type-check   # Run TypeScript checks

# Production
npm start            # Start stdio server
npm run start:stdio  # Start stdio server explicitly  
npm run start:http   # Start HTTP server
```

### Code Quality

- **TypeScript** with strict type checking
- **ESLint** with TypeScript rules
- **Prettier** formatting (coming soon)
- **Husky** git hooks (coming soon)
- **Jest** testing (coming soon)

## 📚 Examples (Coming Soon)

The template will include comprehensive examples of:

### Resources
- Static resources with different content types
- Dynamic resources with URI templates
- File system resources
- API-based resources with pagination

### Tools
- Mathematical calculators with validation
- File system operations
- HTTP API calls with error handling
- Data processing with progress tracking

### Prompts
- Data analysis workflows
- Code generation templates
- Content creation prompts
- Dynamic prompt generation

### Sampling
- Server-initiated LLM conversations
- Recursive agentic behaviors
- Context-aware sampling strategies

## 🔒 Security (Planned)

### OAuth 2.0 Integration
- Complete authorization server implementation
- JWT token validation and refresh
- Scope-based access control
- Secure token storage

### Security Best Practices
- HTTPS enforcement in production
- Secure session management
- Rate limiting and DoS protection
- Input validation and sanitization
- Security headers via Helmet

## 📊 Monitoring & Logging

### Logging Features
- Structured JSON logging
- Context-aware log entries
- Request/response tracing
- Error tracking with stack traces
- Configurable log levels

### Monitoring (Planned)
- Health check endpoints
- Metrics collection
- Performance monitoring
- Connection tracking

## 🔧 Troubleshooting

### Common Issues

#### Build Errors

**Issue**: TypeScript compilation errors during `npm run build`
```bash
error TS2307: Cannot find module '@modelcontextprotocol/sdk'
```

**Solution**: Ensure all dependencies are installed
```bash
rm -rf node_modules package-lock.json
npm install
npm run build
```

**Issue**: ESLint errors preventing build
```bash
npm run lint:fix  # Auto-fix common issues
npm run build
```

#### Runtime Issues

**Issue**: Server fails to start with "Port already in use"
```bash
Error: listen EADDRINUSE :::3000
```

**Solution**: Check and kill processes using the port
```bash
# Find process using port 3000
lsof -ti:3000 | xargs kill -9

# Or use a different port
HTTP_PORT=3001 npm run start:http
```

**Issue**: `MODULE_NOT_FOUND` errors in production
```bash
Error: Cannot find module './dist/index.js'
```

**Solution**: Build the project before running
```bash
npm run build
npm start
```

#### Claude Desktop Integration Issues

**Issue**: Server not appearing in Claude Desktop

**Solution**: Check configuration and file paths
1. Verify `claude_desktop_config.json` location
2. Use absolute paths in configuration
3. Check server logs for errors:

```json
{
  "mcpServers": {
    "mcp-server-template": {
      "command": "node",
      "args": ["/absolute/path/to/dist/stdio-server.js"],
      "env": {
        "LOG_LEVEL": "debug"
      }
    }
  }
}
```

4. Test server independently:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' | node dist/stdio-server.js
```

#### HTTP Transport Issues

**Issue**: CORS errors in browser
```
Access to fetch at 'http://localhost:3000/mcp' from origin 'http://localhost:8080' has been blocked by CORS policy
```

**Solution**: Update CORS configuration in `.env`
```bash
CORS_ORIGIN=http://localhost:8080,http://localhost:3000
# Or allow all origins (development only)
CORS_ORIGIN=*
```

**Issue**: Session issues or authentication problems

**Solution**: Check session configuration
```bash
# Generate secure session secret
SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
echo "SESSION_SECRET=$SESSION_SECRET" >> .env
```

### Debugging

#### Enable Debug Logging

```bash
# Development
LOG_LEVEL=debug npm run dev

# Production
LOG_LEVEL=debug npm run start:http
```

#### Monitor Server Health

```bash
# Health check endpoint
curl -v http://localhost:3000/health

# Check server logs
tail -f logs/mcp-server.log

# Monitor with PM2
pm2 logs mcp-server-template-http
```

#### Test MCP Protocol Communication

```bash
# Test initialize handshake
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {
        "name": "test-client",
        "version": "1.0.0"
      }
    }
  }'

# List resources
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}'
```

### Performance Optimization

#### Memory Usage

Monitor and optimize memory usage:

```bash
# Monitor memory usage
node --inspect dist/http-server.js

# Limit memory in production
node --max-old-space-size=1024 dist/http-server.js
```

#### Connection Limits

For high-traffic scenarios, adjust connection limits:

```javascript
// In your HTTP server configuration
server.maxConnections = 1000;
server.timeout = 30000; // 30 seconds
server.keepAliveTimeout = 5000; // 5 seconds
```

### Getting Help

1. **Check the logs**: Always start by examining server logs
2. **Test in isolation**: Test stdio and HTTP transports separately
3. **Verify configuration**: Double-check environment variables and paths
4. **Check permissions**: Ensure proper file and directory permissions
5. **Update dependencies**: Keep MCP SDK and other dependencies up to date

```bash
npm outdated
npm update @modelcontextprotocol/sdk
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests (when available)
5. Run linting and type checks
6. Submit a pull request

### Development Guidelines
- Use TypeScript with strict typing
- Follow existing code style
- Add comprehensive error handling
- Include logging for important operations
- Update documentation for new features

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📖 API Reference

### MCP Protocol Methods

This server implements the full MCP protocol specification:

#### Core Methods

- `initialize` - Initialize the MCP connection
- `ping` - Health check and connection test
- `notifications/initialized` - Confirm successful initialization

#### Resource Methods

- `resources/list` - List all available resources
- `resources/read` - Read resource content
- `resources/templates/list` - List resource templates
- `resources/subscribe` - Subscribe to resource changes (planned)
- `resources/unsubscribe` - Unsubscribe from resource changes (planned)

#### Tool Methods

- `tools/list` - List all available tools
- `tools/call` - Execute a tool with parameters

#### Prompt Methods

- `prompts/list` - List all available prompts
- `prompts/get` - Get a specific prompt template

#### Sampling Methods (Planned)

- `sampling/createMessage` - Create a message for LLM sampling
- `sampling/listSamples` - List available sampling contexts

### HTTP Endpoints

#### Health and Status

```bash
GET /health
```
Returns server health status and basic information.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 12345,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### MCP Communication

```bash
POST /mcp
Content-Type: application/json
```
Main MCP communication endpoint supporting streaming responses.

**Request Format:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "resources/list",
  "params": {}
}
```

#### Session Management

```bash
DELETE /session/:sessionId
```
Terminate a specific session and cleanup resources.

**Response:**
```json
{
  "success": true,
  "message": "Session terminated"
}
```

### Configuration Options

#### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_NAME` | `mcp-server-template` | Server identifier |
| `SERVER_VERSION` | `1.0.0` | Server version |
| `NODE_ENV` | `development` | Runtime environment |

#### HTTP Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PORT` | `3000` | HTTP server port |
| `HTTP_HOST` | `localhost` | HTTP server host |
| `SESSION_SECRET` | - | Session encryption key |

#### Security Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGIN` | `http://localhost:3000` | Allowed CORS origins |
| `CORS_CREDENTIALS` | `true` | Enable CORS credentials |
| `RATE_LIMIT_WINDOW_MS` | `900000` | Rate limit window (15 min) |
| `RATE_LIMIT_MAX_REQUESTS` | `100` | Max requests per window |

#### Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Minimum log level |
| `LOG_FORMAT` | `json` | Log output format |

### Resource Types

The server provides several types of resources:

#### Static Resources

- **URI Pattern**: `static://server/*`
- **Description**: Fixed content that doesn't change
- **Examples**: Server info, documentation, configuration

#### Dynamic Resources

- **URI Pattern**: `dynamic://data/*`
- **Description**: Computed content based on parameters
- **Examples**: System status, real-time metrics

#### File System Resources

- **URI Pattern**: `file:///*` 
- **Description**: Files from the local file system
- **Examples**: Configuration files, logs, documentation

#### API Resources

- **URI Pattern**: `api://service/*`
- **Description**: Data fetched from external APIs
- **Examples**: Weather data, stock prices, external service status

### Error Handling

The server uses standard JSON-RPC error codes:

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON was received |
| -32600 | Invalid Request | The JSON sent is not a valid Request object |
| -32601 | Method not found | The method does not exist |
| -32602 | Invalid params | Invalid method parameter(s) |
| -32603 | Internal error | Internal JSON-RPC error |
| -32000 | Server error | Generic server error |

**Example Error Response:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method not found",
    "data": {
      "method": "unknown/method"
    }
  },
  "id": 1
}
```

## 🆘 Support

- 📚 [MCP Documentation](https://modelcontextprotocol.io)
- 🔧 [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- 💬 [GitHub Issues](https://github.com/your-org/mcp-server-template/issues)

## 🗺️ Roadmap

- [x] Core MCP server implementation
- [x] Stdio transport
- [x] HTTP transport with CORS and sessions
- [x] Progress tracking utilities
- [x] Cancellation token system
- [ ] OAuth 2.0 authentication
- [ ] Comprehensive resource examples
- [ ] Tool examples with validation
- [ ] Prompt templates
- [ ] Sampling capabilities
- [ ] Advanced pagination
- [ ] Documentation and guides
- [ ] Testing suite
- [ ] Docker support
- [ ] GitHub Actions CI/CD

---

**Built with ❤️ for the MCP community**