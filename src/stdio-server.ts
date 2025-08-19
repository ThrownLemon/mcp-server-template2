#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createMCPServer } from './server.js';
import { logger } from './utils/logger.js';

async function main() {
  try {
    logger.info('Starting MCP server with stdio transport');
    
    const mcpServer = createMCPServer();
    mcpServer.setupGracefulShutdown();

    const transport = new StdioServerTransport();
    await mcpServer.connect(transport);
    
    logger.info('MCP server connected via stdio transport');
  } catch (error) {
    logger.error('Failed to start MCP server', error as Error);
    process.exit(1);
  }
}

// Check if this module is being run directly
const isMainModule = () => {
  if (!process.argv[1]) return true;
  const modulePath = new URL(import.meta.url).pathname;
  const scriptPath = process.argv[1].replace(/\\/g, '/');
  return modulePath.includes(scriptPath) || scriptPath.includes('stdio-server');
};

if (isMainModule()) {
  main().catch((error) => {
    logger.error('Unhandled error in main', error);
    process.exit(1);
  });
}