import { EventEmitter } from 'events';
import { logger } from './logger.js';

export interface PingStatus {
  isHealthy: boolean;
  lastPing: Date;
  responseTime?: number;
  consecutiveFailures: number;
  uptime: number;
}

export interface HeartbeatOptions {
  interval: number; // milliseconds
  timeout: number; // milliseconds
  maxFailures: number;
  enabled: boolean;
}

export class HeartbeatManager extends EventEmitter {
  private _status: PingStatus;
  private _options: HeartbeatOptions;
  private _intervalHandle?: NodeJS.Timeout;
  private _startTime: Date;
  private _isRunning = false;

  constructor(options: Partial<HeartbeatOptions> = {}) {
    super();
    
    this._options = {
      interval: options.interval ?? 30000, // 30 seconds
      timeout: options.timeout ?? 5000, // 5 seconds
      maxFailures: options.maxFailures ?? 3,
      enabled: options.enabled ?? true
    };

    this._startTime = new Date();
    this._status = {
      isHealthy: true,
      lastPing: new Date(),
      consecutiveFailures: 0,
      uptime: 0
    };
  }

  get status(): PingStatus {
    return {
      ...this._status,
      uptime: Date.now() - this._startTime.getTime()
    };
  }

  get options(): HeartbeatOptions {
    return { ...this._options };
  }

  get isRunning(): boolean {
    return this._isRunning;
  }

  start(): void {
    if (this._isRunning || !this._options.enabled) {
      return;
    }

    this._isRunning = true;
    logger.info('Starting heartbeat manager', {
      interval: this._options.interval,
      timeout: this._options.timeout,
      maxFailures: this._options.maxFailures
    });

    this._scheduleNextPing();
    this.emit('started');
  }

  stop(): void {
    if (!this._isRunning) {
      return;
    }

    this._isRunning = false;
    
    if (this._intervalHandle) {
      clearTimeout(this._intervalHandle);
      this._intervalHandle = undefined;
    }

    logger.info('Stopped heartbeat manager');
    this.emit('stopped');
  }

  async ping(): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      // Simulate a health check - in real implementation this would
      // check database connections, external APIs, etc.
      await this._performHealthCheck();
      
      const responseTime = Date.now() - startTime;
      this._status = {
        isHealthy: true,
        lastPing: new Date(),
        responseTime,
        consecutiveFailures: 0,
        uptime: Date.now() - this._startTime.getTime()
      };

      this.emit('ping-success', this._status);
      return true;

    } catch (error) {
      this._status.consecutiveFailures++;
      this._status.lastPing = new Date();
      this._status.responseTime = Date.now() - startTime;
      this._status.uptime = Date.now() - this._startTime.getTime();

      // Mark as unhealthy if we've exceeded max failures
      if (this._status.consecutiveFailures >= this._options.maxFailures) {
        this._status.isHealthy = false;
      }

      logger.warn('Health check failed', {
        error: error instanceof Error ? error.message : error,
        consecutiveFailures: this._status.consecutiveFailures,
        isHealthy: this._status.isHealthy
      });

      this.emit('ping-failure', { ...this._status, error });
      
      if (!this._status.isHealthy) {
        this.emit('unhealthy', this._status);
      }

      return false;
    }
  }

  updateOptions(options: Partial<HeartbeatOptions>): void {
    const oldOptions = this._options;
    this._options = { ...this._options, ...options };

    // Restart if interval changed and we're running
    if (this._isRunning && oldOptions.interval !== this._options.interval) {
      this.stop();
      this.start();
    }

    this.emit('options-updated', this._options);
  }

  private _scheduleNextPing(): void {
    if (!this._isRunning) {
      return;
    }

    this._intervalHandle = setTimeout(async () => {
      await this.ping();
      this._scheduleNextPing();
    }, this._options.interval);
  }

  private async _performHealthCheck(): Promise<void> {
    // Simulate health check with configurable delay
    const delay = Math.random() * 100 + 50; // 50-150ms
    
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        // Simulate occasional failures for testing
        if (Math.random() < 0.05) { // 5% failure rate
          reject(new Error('Health check simulation failure'));
        } else {
          resolve();
        }
      }, delay);
    });
  }

  // Health check methods that can be customized
  addHealthCheck(name: string, checkFn: () => Promise<boolean>): void {
    // This would be expanded to support custom health checks
    logger.debug('Health check registered', { name });
  }
}

// Global heartbeat manager instance
export const globalHeartbeat = new HeartbeatManager();

// HTTP endpoint helpers
export const createHealthResponse = (status: PingStatus) => ({
  status: status.isHealthy ? 'healthy' : 'unhealthy',
  timestamp: new Date().toISOString(),
  uptime: status.uptime,
  lastPing: status.lastPing.toISOString(),
  responseTime: status.responseTime,
  consecutiveFailures: status.consecutiveFailures,
  details: {
    service: 'mcp-server-template',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  }
});

export const createPingResponse = (responseTime: number) => ({
  pong: true,
  timestamp: new Date().toISOString(),
  responseTime,
  server: 'mcp-server-template'
});