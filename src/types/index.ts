export interface ServerConfig {
  name: string;
  version: string;
  description?: string;
  author?: string;
}

export interface HttpConfig {
  port: number;
  host: string;
  cors: {
    origin: string | string[] | boolean;
    credentials: boolean;
  };
  session: {
    secret: string;
    name?: string;
    maxAge?: number;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
}

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  issuer: string;
  scopes: string[];
}

export interface LoggingConfig {
  level: string;
  format: 'json' | 'simple';
}

export interface PaginationConfig {
  defaultPageSize: number;
  maxPageSize: number;
}

export interface ProgressTracker {
  id: string;
  total: number;
  current: number;
  status: 'pending' | 'running' | 'completed' | 'failed';
  message?: string | undefined;
  startTime: Date;
  endTime?: Date | undefined;
}

export interface CancellationToken {
  isCancelled: boolean;
  reason?: string | undefined;
  cancel(reason?: string): void;
  onCancelled(callback: (reason?: string) => void): void;
}

export interface PaginationOptions {
  page?: number;
  size?: number;
  cursor?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page?: number;
    size: number;
    total?: number;
    hasNext: boolean;
    hasPrev: boolean;
    nextCursor?: string;
    prevCursor?: string;
  };
}

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: string;
  expiresIn: number;
  scope?: string;
}