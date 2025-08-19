import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { globalProgressManager } from '../utils/progress.js';
import { globalHeartbeat } from '../utils/ping.js';
import { logger } from '../utils/logger.js';

export function setupUtilityExamples(server: McpServer): void {
  logger.info('Setting up utility examples');

  // Simple health check tool
  server.tool(
    'health-check',
    'Get comprehensive server health status including heartbeat, uptime, and service details',
    async () => {
      const status = globalHeartbeat.status;
      const options = globalHeartbeat.options;
      const isRunning = globalHeartbeat.isRunning;
      
      const healthEmoji = status.isHealthy ? '🟢' : '🔴';
      const runningEmoji = isRunning ? '▶️' : '⏸️';
      
      let content = `${healthEmoji} **Server Health Status**\n\n`;
      content += `Status: ${status.isHealthy ? 'Healthy' : 'Unhealthy'}\n`;
      content += `${runningEmoji} Heartbeat: ${isRunning ? 'Running' : 'Stopped'}\n`;
      content += `Uptime: ${Math.round(status.uptime / 1000)} seconds\n`;
      content += `Last Ping: ${status.lastPing.toISOString()}\n`;
      
      if (status.responseTime) {
        content += `Response Time: ${status.responseTime}ms\n`;
      }
      
      content += `Consecutive Failures: ${status.consecutiveFailures}\n`;
      
      content += `\n**Configuration:**\n`;
      content += `Ping Interval: ${options.interval}ms (${options.interval / 1000}s)\n`;
      content += `Timeout: ${options.timeout}ms\n`;
      content += `Max Failures: ${options.maxFailures}\n`;
      content += `Enabled: ${options.enabled}\n`;
      
      content += `\n**Available HTTP Endpoints:**\n`;
      content += `• GET /health - Comprehensive health status\n`;
      content += `• GET /ping - Simple connectivity test\n`;
      content += `• GET /heartbeat - Detailed heartbeat information\n`;
      content += `• GET /progress - List all progress trackers\n`;
      content += `• GET /progress/:id - Specific progress details\n`;
      
      return {
        content: [{
          type: 'text',
          text: content
        }]
      };
    }
  );

  // Progress monitoring tool
  server.tool(
    'list-progress',
    'List all current progress trackers. Shows active and completed tasks with their status',
    async () => {
      const trackers = globalProgressManager.getAll();
      
      if (trackers.length === 0) {
        return {
          content: [{
            type: 'text',
            text: '📝 **No Progress Trackers Found**\n\nNo tasks are currently being tracked. You can:\n\n• Use the simulate-long-task tool to create a test progress tracker\n• Check HTTP endpoint: GET /progress\n• Monitor individual tasks: GET /progress/:taskId'
          }]
        };
      }
      
      const progressList = trackers.map(tracker => {
        const progress = tracker.toJSON();
        const emoji = {
          pending: '⏳',
          running: '🔄',
          completed: '✅',
          failed: '❌'
        }[progress.status];
        
        const duration = progress.endTime ? 
          Math.round((new Date(progress.endTime).getTime() - new Date(progress.startTime).getTime()) / 1000) : 
          Math.round((Date.now() - new Date(progress.startTime).getTime()) / 1000);
          
        return `${emoji} **${progress.id}**\n  Status: ${progress.status} (${progress.percentage}%)\n  Message: ${progress.message}\n  Duration: ${duration}s\n  Progress: ${progress.current}/${progress.total}`;
      }).join('\n\n');
      
      return {
        content: [{
          type: 'text',
          text: `📊 **Progress Trackers** (${trackers.length} total)\n\n${progressList}\n\n**HTTP Endpoints:**\n• GET /progress - JSON list of all trackers\n• GET /progress/:id - Detailed progress information`
        }]
      };
    }
  );

  // Utility information tool
  server.tool(
    'utility-info',
    'Get information about all available utilities: cancellation, progress tracking, heartbeat, and logging',
    async () => {
      return {
        content: [{
          type: 'text',
          text: `🛠️ **MCP Server Utilities Overview**\n\n` +
                `**1. 🔄 Progress Tracking**\n` +
                `- Real-time progress monitoring with events\n` +
                `- Automatic cleanup after completion\n` +
                `- HTTP endpoints: /progress, /progress/:id\n` +
                `- Global ProgressManager with tracking capabilities\n\n` +
                
                `**2. 💓 Heartbeat & Health Monitoring**\n` +
                `- Automatic health checks every 30 seconds\n` +
                `- Configurable failure detection (3 max failures)\n` +
                `- HTTP endpoints: /health, /ping, /heartbeat\n` +
                `- Real-time status monitoring\n\n` +
                
                `**3. 🛑 Cancellation Support**\n` +
                `- CancellationToken system for graceful termination\n` +
                `- Timeout tokens and combined cancellation\n` +
                `- throwIfCancelled() for operation checking\n` +
                `- Used internally for all long-running operations\n\n` +
                
                `**4. 📝 Enhanced Logging**\n` +
                `- Structured JSON logging with Winston\n` +
                `- Context-aware request tracking\n` +
                `- Transport-specific log handling\n` +
                `- File-based logging in stdio mode\n\n` +
                
                `**5. 🔔 Notification Debouncing**\n` +
                `- MCP server configured with debounced notifications\n` +
                `- Prevents spam during bulk tool/resource updates\n` +
                `- Optimizes client performance\n\n` +
                
                `**Available Tools:**\n` +
                `• health-check - Server health status\n` +
                `• list-progress - Current progress trackers\n` +
                `• utility-info - This information summary\n\n` +
                
                `**HTTP Endpoints for Testing:**\n` +
                `• GET /health - Health status (200=healthy, 503=unhealthy)\n` +
                `• GET /ping - Simple connectivity test\n` +
                `• GET /heartbeat - Detailed heartbeat info\n` +
                `• GET /progress - All progress trackers\n` +
                `• GET /progress/:id - Specific progress details`
        }]
      };
    }
  );

  logger.info('Utility examples setup completed');
}