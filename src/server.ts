import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { serverConfig } from './utils/config.js';
import { logger } from './utils/logger.js';
import { setupExampleResources } from './examples/resources.js';
import { setupExampleTools } from './examples/tools.js';
import { setupExamplePrompts } from './examples/prompts.js';
import { setupSampling } from './examples/sampling.js';
import { setupUtilityExamples } from './examples/utilities-simple.js';

export class MCPServerTemplate {
  public readonly server: McpServer;
  private _isRunning = false;

  constructor() {
    this.server = new McpServer(
      {
        name: serverConfig.name,
        version: serverConfig.version
      },
      {
        // Enable notification debouncing for efficient batch updates
        debouncedNotificationMethods: [
          'notifications/tools/list_changed',
          'notifications/resources/list_changed',
          'notifications/prompts/list_changed'
        ]
      }
    );

    this.setupExamples();
  }

  private setupExamples(): void {
    // Set up all example functionality
    setupExampleResources(this.server);
    setupExampleTools(this.server);
    setupExamplePrompts(this.server);
    setupSampling(this.server);
    setupUtilityExamples(this.server);
  }

  get isRunning(): boolean {
    return this._isRunning;
  }

  async connect(transport: any): Promise<void> {
    logger.info('Connecting MCP server to transport');
    await this.server.connect(transport);
    this._isRunning = true;
    logger.info('MCP server connected successfully');
  }

  async shutdown(): Promise<void> {
    logger.info('Shutting down MCP server');
    this._isRunning = false;
    await this.server.close();
  }

  // Handle graceful shutdown
  setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      logger.info(`Received ${signal}, shutting down gracefully`);
      await this.shutdown();
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', error);
      shutdown('UNCAUGHT_EXCEPTION');
    });
    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled rejection', new Error(String(reason)));
      shutdown('UNHANDLED_REJECTION');
    });
  }
}

export const createMCPServer = (): MCPServerTemplate => {
  return new MCPServerTemplate();
};