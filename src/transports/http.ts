import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { httpConfig } from '../utils/config.js';
import { logger, createContextLogger } from '../utils/logger.js';

export interface SessionTransports {
  streamable: Record<string, StreamableHTTPServerTransport>;
  sse: Record<string, SSEServerTransport>;
}

export class HTTPTransportManager {
  private app: Application;
  private transports: SessionTransports = {
    streamable: {},
    sse: {}
  };

  constructor(private mcpServer: McpServer) {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          connectSrc: ["'self'"]
        }
      }
    }));

    // CORS middleware
    this.app.use(cors({
      origin: httpConfig.cors.origin,
      credentials: httpConfig.cors.credentials,
      methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-session-id']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: httpConfig.rateLimit.windowMs,
      max: httpConfig.rateLimit.maxRequests,
      message: {
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Rate limit exceeded'
        },
        id: null
      },
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use(limiter);

    // Session management
    this.app.use(session({
      secret: httpConfig.session.secret,
      name: httpConfig.session.name,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: httpConfig.session.maxAge
      }
    }));

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request logging
    this.app.use((req, res, next) => {
      const reqLogger = createContextLogger({
        requestId: req.sessionID,
        method: req.method,
        url: req.url
      });
      
      reqLogger.info('HTTP request received');
      
      res.on('finish', () => {
        reqLogger.info('HTTP request completed', {
          statusCode: res.statusCode,
          contentLength: res.get('content-length')
        });
      });

      next();
    });
  }

  private setupRoutes(): void {
    // Health check endpoint
    this.app.get('/health', (req: Request, res: Response) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'mcp-server-template'
      });
    });

    // Modern Streamable HTTP endpoint (stateful with session management)
    this.app.all('/mcp', async (req: Request, res: Response) => {
      await this.handleStreamableHTTP(req, res);
    });

    // Backwards compatibility: Legacy SSE endpoint
    this.app.get('/sse', async (req: Request, res: Response) => {
      await this.handleSSEConnection(req, res);
    });

    // Backwards compatibility: Legacy message endpoint for SSE
    this.app.post('/messages', async (req: Request, res: Response) => {
      await this.handleSSEMessage(req, res);
    });

    // Session termination endpoint
    this.app.delete('/session/:sessionId', async (req: Request, res: Response) => {
      await this.handleSessionTermination(req, res);
    });

    // Progress endpoint for long-running operations
    this.app.get('/progress/:progressId', (req: Request, res: Response) => {
      // Implementation will be added with progress utilities
      res.json({ message: 'Progress tracking not implemented yet' });
    });

    // Error handling middleware
    this.app.use((error: Error, req: Request, res: Response, _next: any) => {
      const reqLogger = createContextLogger({
        requestId: req.sessionID,
        operation: 'error-handler'
      });

      reqLogger.error('Unhandled error in HTTP transport', error);

      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error'
          },
          id: null
        });
      }
    });

    // 404 handler
    this.app.use((req: Request, res: Response) => {
      res.status(404).json({
        jsonrpc: '2.0',
        error: {
          code: -32601,
          message: 'Endpoint not found'
        },
        id: null
      });
    });
  }

  private async handleStreamableHTTP(req: Request, res: Response): Promise<void> {
    const sessionId = req.sessionID;
    const reqLogger = createContextLogger({
      requestId: sessionId,
      operation: 'streamable-http'
    });

    try {
      // Get or create transport for this session
      let transport = this.transports.streamable[sessionId];
      
      if (!transport) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => sessionId
        });
        
        this.transports.streamable[sessionId] = transport;
        
        // Clean up on disconnect
        res.on('close', () => {
          reqLogger.info('Client disconnected, cleaning up transport');
          transport?.close();
          delete this.transports.streamable[sessionId];
        });

        await this.mcpServer.connect(transport);
        reqLogger.info('New streamable HTTP transport connected');
      }

      await transport.handleRequest(req, res, req.body);
      
    } catch (error) {
      reqLogger.error('Error in streamable HTTP handler', error as Error);
      
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error'
          },
          id: null
        });
      }
    }
  }

  private async handleSSEConnection(req: Request, res: Response): Promise<void> {
    const sessionId = req.sessionID;
    const reqLogger = createContextLogger({
      requestId: sessionId,
      operation: 'sse-connection'
    });

    try {
      // Create SSE transport for legacy clients
      const transport = new SSEServerTransport('/messages', res);
      this.transports.sse[sessionId] = transport;

      res.on('close', () => {
        reqLogger.info('SSE client disconnected, cleaning up transport');
        delete this.transports.sse[sessionId];
      });

      await this.mcpServer.connect(transport);
      reqLogger.info('SSE transport connected for legacy client');
      
    } catch (error) {
      reqLogger.error('Error in SSE connection handler', error as Error);
      
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error'
          },
          id: null
        });
      }
    }
  }

  private async handleSSEMessage(req: Request, res: Response): Promise<void> {
    const sessionId = req.query.sessionId as string || req.sessionID;
    const transport = this.transports.sse[sessionId];
    
    const reqLogger = createContextLogger({
      requestId: sessionId,
      operation: 'sse-message'
    });

    if (!transport) {
      reqLogger.warn('No SSE transport found for session');
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'No transport found for session'
        },
        id: null
      });
      return;
    }

    try {
      await transport.handlePostMessage(req, res, req.body);
    } catch (error) {
      reqLogger.error('Error in SSE message handler', error as Error);
      
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error'
          },
          id: null
        });
      }
    }
  }

  private async handleSessionTermination(req: Request, res: Response): Promise<void> {
    const sessionId = req.params.sessionId;
    
    if (!sessionId) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Session ID is required'
        },
        id: null
      });
      return;
    }

    const reqLogger = createContextLogger({
      requestId: sessionId,
      operation: 'session-termination'
    });

    try {
      // Clean up streamable transport
      const streamableTransport = this.transports.streamable[sessionId];
      if (streamableTransport) {
        await streamableTransport.close();
        delete this.transports.streamable[sessionId];
        reqLogger.info('Streamable transport terminated');
      }

      // Clean up SSE transport
      const sseTransport = this.transports.sse[sessionId];
      if (sseTransport) {
        await sseTransport.close();
        delete this.transports.sse[sessionId];
        reqLogger.info('SSE transport terminated');
      }

      res.json({ 
        message: 'Session terminated successfully',
        sessionId 
      });
      
    } catch (error) {
      reqLogger.error('Error in session termination handler', error as Error);
      
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Failed to terminate session'
          },
          id: null
        });
      }
    }
  }

  getApp(): Application {
    return this.app;
  }

  async listen(port: number, host: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = this.app.listen(port, host, () => {
        logger.info(`HTTP transport listening on ${host}:${port}`);
        resolve();
      });

      server.on('error', (error) => {
        logger.error('Failed to start HTTP server', error);
        reject(error);
      });
    });
  }

  async close(): Promise<void> {
    // Close all active transports
    for (const transport of Object.values(this.transports.streamable)) {
      await transport.close();
    }
    
    for (const transport of Object.values(this.transports.sse)) {
      await transport.close();
    }

    this.transports.streamable = {};
    this.transports.sse = {};
    
    logger.info('HTTP transport closed');
  }
}