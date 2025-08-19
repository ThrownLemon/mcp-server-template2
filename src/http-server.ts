#!/usr/bin/env node
import { createMCPServer } from './server.js';
import { HTTPTransportManager } from './transports/http.js';
import { httpConfig } from './utils/config.js';
import { logger } from './utils/logger.js';

async function main() {
  try {
    logger.info('Starting MCP server with HTTP transport');
    
    const mcpServer = createMCPServer();
    mcpServer.setupGracefulShutdown();

    const httpTransport = new HTTPTransportManager(mcpServer.server);
    
    // Set up graceful shutdown for HTTP transport
    const shutdownHTTP = async () => {
      logger.info('Shutting down HTTP transport');
      await httpTransport.close();
      await mcpServer.shutdown();
    };

    process.on('SIGTERM', shutdownHTTP);
    process.on('SIGINT', shutdownHTTP);

    await httpTransport.listen(httpConfig.port, httpConfig.host);
    
    logger.info('MCP server with HTTP transport started successfully', {
      port: httpConfig.port,
      host: httpConfig.host,
      endpoints: {
        health: `http://${httpConfig.host}:${httpConfig.port}/health`,
        mcp: `http://${httpConfig.host}:${httpConfig.port}/mcp`,
        sse: `http://${httpConfig.host}:${httpConfig.port}/sse`,
        messages: `http://${httpConfig.host}:${httpConfig.port}/messages`
      }
    });
    
  } catch (error) {
    logger.error('Failed to start MCP server with HTTP transport', error as Error);
    process.exit(1);
  }
}

// Check if this module is being run directly
const isMainModule = () => {
  if (!process.argv[1]) return true;
  const modulePath = new URL(import.meta.url).pathname;
  const scriptPath = process.argv[1].replace(/\\/g, '/');
  return modulePath.includes(scriptPath) || scriptPath.includes('http-server');
};

if (isMainModule()) {
  main().catch((error) => {
    logger.error('Unhandled error in main', error);
    process.exit(1);
  });
}