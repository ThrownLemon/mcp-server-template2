import winston from 'winston';
import { loggingConfig } from './config.js';

const logFormat = loggingConfig.format === 'json' 
  ? winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    )
  : winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.simple()
    );

export const logger = winston.createLogger({
  level: loggingConfig.level,
  format: logFormat,
  defaultMeta: { service: 'mcp-server-template' },
  transports: [
    new winston.transports.Console({
      format: loggingConfig.format === 'json' 
        ? winston.format.json()
        : winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
    })
  ]
});

export interface LogContext {
  requestId?: string;
  userId?: string;
  operation?: string;
  duration?: number;
  [key: string]: unknown;
}

export const createContextLogger = (context: LogContext) => ({
  info: (message: string, meta?: object) => 
    logger.info(message, { ...context, ...meta }),
  warn: (message: string, meta?: object) => 
    logger.warn(message, { ...context, ...meta }),
  error: (message: string, error?: Error, meta?: object) => 
    logger.error(message, { ...context, error: error?.stack, ...meta }),
  debug: (message: string, meta?: object) => 
    logger.debug(message, { ...context, ...meta })
});