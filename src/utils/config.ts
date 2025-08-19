import { config as dotenvConfig } from 'dotenv';
import type { 
  ServerConfig, 
  HttpConfig, 
  OAuthConfig, 
  LoggingConfig, 
  PaginationConfig 
} from '../types/index.js';

dotenvConfig();

export const serverConfig: ServerConfig = {
  name: process.env.SERVER_NAME ?? 'mcp-server-template',
  version: process.env.SERVER_VERSION ?? '1.0.0',
  description: 'A comprehensive MCP server template with all latest features',
  author: 'MCP Community'
};

export const httpConfig: HttpConfig = {
  port: parseInt(process.env.HTTP_PORT ?? '3000', 10),
  host: process.env.HTTP_HOST ?? 'localhost',
  cors: {
    origin: process.env.CORS_ORIGIN ?? 'http://localhost:3000',
    credentials: process.env.CORS_CREDENTIALS === 'true'
  },
  session: {
    secret: process.env.SESSION_SECRET ?? 'change-this-in-production',
    name: 'mcp-session',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '900000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS ?? '100', 10)
  }
};

export const oauthConfig: OAuthConfig = {
  clientId: process.env.OAUTH_CLIENT_ID ?? '',
  clientSecret: process.env.OAUTH_CLIENT_SECRET ?? '',
  redirectUri: process.env.OAUTH_REDIRECT_URI ?? 'http://localhost:3000/auth/callback',
  issuer: process.env.OAUTH_ISSUER ?? '',
  scopes: (process.env.OAUTH_SCOPES ?? 'openid,profile,email').split(',')
};

export const loggingConfig: LoggingConfig = {
  level: process.env.LOG_LEVEL ?? 'info',
  format: (process.env.LOG_FORMAT as 'json' | 'simple') ?? 'json'
};

export const paginationConfig: PaginationConfig = {
  defaultPageSize: parseInt(process.env.DEFAULT_PAGE_SIZE ?? '50', 10),
  maxPageSize: parseInt(process.env.MAX_PAGE_SIZE ?? '1000', 10)
};

export const progressUpdateInterval = parseInt(
  process.env.PROGRESS_UPDATE_INTERVAL ?? '1000', 
  10
);