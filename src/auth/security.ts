import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import * as crypto from 'crypto';

/**
 * OAuth 2.0 Security Enhancements
 * 
 * This module provides comprehensive security measures for OAuth 2.0 implementation
 * including rate limiting, input validation, CSRF protection, and security headers.
 */

// Rate limiters for different OAuth endpoints
export const oauthRateLimiters = {
  // Authorization endpoint - more lenient as users may retry
  authorization: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 requests per window per IP
    message: {
      error: 'too_many_requests',
      error_description: 'Too many authorization requests. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      // Rate limit by IP and client_id combination
      const clientId = req.query.client_id as string || 'unknown';
      return `${req.ip}-${clientId}`;
    },
    onLimitReached: (req: Request) => {
      logger.warn('OAuth authorization rate limit reached', {
        ip: req.ip,
        clientId: req.query.client_id,
        userAgent: req.get('user-agent')
      });
    }
  }),

  // Token endpoint - stricter as it's API-based
  token: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per window per IP
    message: {
      error: 'too_many_requests',
      error_description: 'Too many token requests. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      // Rate limit by IP and client_id combination
      const clientId = req.body.client_id || 'unknown';
      return `${req.ip}-${clientId}`;
    },
    onLimitReached: (req: Request) => {
      logger.warn('OAuth token rate limit reached', {
        ip: req.ip,
        clientId: req.body.client_id,
        grantType: req.body.grant_type
      });
    }
  }),

  // Client management endpoints - very strict
  clientManagement: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 requests per hour per IP
    message: {
      error: 'too_many_requests',
      error_description: 'Too many client management requests. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    onLimitReached: (req: Request) => {
      logger.warn('Client management rate limit reached', {
        ip: req.ip,
        method: req.method,
        path: req.path
      });
    }
  }),

  // Revocation endpoint - moderate limits
  revocation: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // 50 requests per window per IP
    message: {
      error: 'too_many_requests',
      error_description: 'Too many revocation requests. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false
  })
};

/**
 * Input validation utilities for OAuth parameters
 */
export class OAuthInputValidator {
  // Validate client_id format
  static validateClientId(clientId: string): boolean {
    if (!clientId || typeof clientId !== 'string') return false;
    // Client ID should be alphanumeric with hyphens and underscores
    return /^[a-zA-Z0-9_-]{1,100}$/.test(clientId);
  }

  // Validate redirect URI
  static validateRedirectUri(uri: string): { valid: boolean; reason?: string } {
    if (!uri || typeof uri !== 'string') {
      return { valid: false, reason: 'Redirect URI is required' };
    }

    try {
      const url = new URL(uri);
      
      // Check for dangerous protocols
      if (!['http:', 'https:', 'myapp:', 'com.'].some(protocol => uri.startsWith(protocol))) {
        return { valid: false, reason: 'Unsupported URI scheme' };
      }

      // Prevent localhost in production (unless explicitly configured)
      if (process.env.NODE_ENV === 'production' && url.hostname === 'localhost') {
        return { valid: false, reason: 'Localhost not allowed in production' };
      }

      // Prevent fragments in redirect URI
      if (url.hash) {
        return { valid: false, reason: 'Fragment not allowed in redirect URI' };
      }

      // URI length check
      if (uri.length > 2048) {
        return { valid: false, reason: 'Redirect URI too long' };
      }

      return { valid: true };
    } catch (error) {
      return { valid: false, reason: 'Invalid URI format' };
    }
  }

  // Validate scope string
  static validateScope(scope: string): { valid: boolean; reason?: string } {
    if (!scope || typeof scope !== 'string') {
      return { valid: false, reason: 'Scope is required' };
    }

    const scopes = scope.split(' ');
    
    // Check each individual scope
    for (const s of scopes) {
      if (!/^[a-zA-Z0-9_:-]{1,50}$/.test(s)) {
        return { valid: false, reason: `Invalid scope format: ${s}` };
      }
    }

    // Check for duplicates
    if (new Set(scopes).size !== scopes.length) {
      return { valid: false, reason: 'Duplicate scopes not allowed' };
    }

    return { valid: true };
  }

  // Validate state parameter
  static validateState(state: string): boolean {
    if (!state || typeof state !== 'string') return false;
    // State should be printable ASCII characters only
    return /^[\x20-\x7E]{1,255}$/.test(state) && state.length >= 8;
  }

  // Validate code challenge
  static validateCodeChallenge(challenge: string, method: string): boolean {
    if (!challenge || !method) return false;
    
    if (method === 'plain') {
      // Code verifier format (43-128 characters)
      return /^[A-Za-z0-9_~.-]{43,128}$/.test(challenge);
    }
    
    if (method === 'S256') {
      // Base64url encoded SHA256 hash (43 characters)
      return /^[A-Za-z0-9_-]{43}$/.test(challenge);
    }
    
    return false;
  }

  // Validate authorization code format
  static validateAuthorizationCode(code: string): boolean {
    if (!code || typeof code !== 'string') return false;
    // Base64url format, reasonable length
    return /^[A-Za-z0-9_-]{20,255}$/.test(code);
  }

  // Validate token format
  static validateToken(token: string): boolean {
    if (!token || typeof token !== 'string') return false;
    // JWT or opaque token format
    return token.length >= 20 && token.length <= 4096;
  }
}

/**
 * Security headers middleware for OAuth endpoints
 */
export function addOAuthSecurityHeaders(req: Request, res: Response, next: Function): void {
  // Prevent caching of sensitive endpoints
  res.set({
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Expires': '0'
  });

  // Content security policy for OAuth pages
  if (req.path.includes('/oauth/authorize')) {
    res.set('Content-Security-Policy', 
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https:; " +
      "form-action 'self'; " +
      "frame-ancestors 'none';"
    );
  }

  // Referrer policy
  res.set('Referrer-Policy', 'no-referrer');

  // XSS protection
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');

  next();
}

/**
 * CSRF protection for OAuth flows
 */
export class CSRFProtection {
  private static readonly SECRET_LENGTH = 32;

  // Generate CSRF token
  static generateToken(): string {
    return crypto.randomBytes(this.SECRET_LENGTH).toString('base64url');
  }

  // Validate CSRF token
  static validateToken(token: string, expectedToken: string): boolean {
    if (!token || !expectedToken) return false;
    
    // Constant-time comparison to prevent timing attacks
    try {
      return crypto.timingSafeEqual(
        Buffer.from(token, 'base64url'),
        Buffer.from(expectedToken, 'base64url')
      );
    } catch {
      return false;
    }
  }

  // Middleware to require CSRF token for state-changing operations
  static requireCSRF(req: Request, res: Response, next: Function): void {
    // Skip CSRF for GET requests and token endpoint (which uses different protection)
    if (req.method === 'GET' || req.path === '/oauth/token') {
      return next();
    }

    const tokenHeader = req.get('X-CSRF-Token');
    const tokenBody = req.body.csrf_token;
    const sessionToken = req.session?.csrfToken;

    const providedToken = tokenHeader || tokenBody;

    if (!providedToken || !sessionToken || !this.validateToken(providedToken, sessionToken)) {
      logger.warn('CSRF token validation failed', {
        ip: req.ip,
        path: req.path,
        hasHeader: !!tokenHeader,
        hasBody: !!tokenBody,
        hasSession: !!sessionToken
      });

      return res.status(403).json({
        error: 'invalid_request',
        error_description: 'Invalid CSRF token'
      });
    }

    next();
  }
}

/**
 * Timing attack protection
 */
export class TimingProtection {
  // Constant-time string comparison
  static safeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    
    try {
      return crypto.timingSafeEqual(
        Buffer.from(a, 'utf8'),
        Buffer.from(b, 'utf8')
      );
    } catch {
      return false;
    }
  }

  // Add random delay to prevent timing attacks
  static async randomDelay(minMs: number = 50, maxMs: number = 200): Promise<void> {
    const delay = Math.random() * (maxMs - minMs) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}

/**
 * Brute force protection
 */
export class BruteForceProtection {
  private static attempts = new Map<string, { count: number; lastAttempt: Date }>();
  private static readonly MAX_ATTEMPTS = 5;
  private static readonly LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

  // Record failed authentication attempt
  static recordFailedAttempt(identifier: string): void {
    const now = new Date();
    const existing = this.attempts.get(identifier);

    if (existing) {
      existing.count++;
      existing.lastAttempt = now;
    } else {
      this.attempts.set(identifier, { count: 1, lastAttempt: now });
    }

    // Clean up old entries
    this.cleanup();
  }

  // Reset attempts for successful authentication
  static resetAttempts(identifier: string): void {
    this.attempts.delete(identifier);
  }

  // Check if identifier is locked out
  static isLockedOut(identifier: string): boolean {
    const record = this.attempts.get(identifier);
    if (!record || record.count < this.MAX_ATTEMPTS) return false;

    const timeSinceLastAttempt = Date.now() - record.lastAttempt.getTime();
    return timeSinceLastAttempt < this.LOCKOUT_DURATION;
  }

  // Clean up expired entries
  private static cleanup(): void {
    const now = Date.now();
    for (const [key, record] of this.attempts.entries()) {
      const age = now - record.lastAttempt.getTime();
      if (age > this.LOCKOUT_DURATION) {
        this.attempts.delete(key);
      }
    }
  }

  // Middleware to check for brute force attempts
  static checkBruteForce(req: Request, res: Response, next: Function): void {
    const identifier = `${req.ip}-${req.body.client_id || req.query.client_id || 'unknown'}`;
    
    if (this.isLockedOut(identifier)) {
      logger.warn('Brute force protection triggered', {
        identifier,
        ip: req.ip,
        path: req.path
      });

      return res.status(429).json({
        error: 'too_many_requests',
        error_description: 'Too many failed attempts. Please try again later.',
        retry_after: Math.ceil(this.LOCKOUT_DURATION / 1000)
      });
    }

    next();
  }
}

/**
 * Audit logging for security events
 */
export class SecurityAuditLogger {
  // Log authentication events
  static logAuthEvent(event: string, details: any, req: Request): void {
    logger.info(`OAuth security event: ${event}`, {
      event,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      clientId: details.clientId,
      userId: details.userId,
      scopes: details.scopes,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  // Log security violations
  static logSecurityViolation(violation: string, details: any, req: Request): void {
    logger.warn(`OAuth security violation: ${violation}`, {
      violation,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      path: req.path,
      method: req.method,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  // Log administrative actions
  static logAdminAction(action: string, details: any, req: Request): void {
    logger.info(`OAuth admin action: ${action}`, {
      action,
      adminIp: req.ip,
      adminAgent: req.get('user-agent'),
      timestamp: new Date().toISOString(),
      ...details
    });
  }
}

/**
 * Token security utilities
 */
export class TokenSecurity {
  // Generate cryptographically secure random string
  static generateSecureRandom(length: number = 32): string {
    return crypto.randomBytes(Math.ceil(length * 3 / 4)).toString('base64url').slice(0, length);
  }

  // Hash sensitive data for logging
  static hashForLogging(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex').slice(0, 8);
  }

  // Validate JWT structure (basic check)
  static validateJWTStructure(token: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    try {
      // Check if parts are valid base64url
      parts.forEach(part => {
        Buffer.from(part, 'base64url');
      });
      return true;
    } catch {
      return false;
    }
  }
}

// Export security configuration
export const securityConfig = {
  // Token expiration times
  tokenTTL: {
    accessToken: 3600, // 1 hour
    refreshToken: 30 * 24 * 3600, // 30 days
    authorizationCode: 600, // 10 minutes
    idToken: 3600 // 1 hour
  },

  // Rate limiting configuration
  rateLimits: {
    authorization: { windowMs: 15 * 60 * 1000, max: 20 },
    token: { windowMs: 15 * 60 * 1000, max: 10 },
    clientManagement: { windowMs: 60 * 60 * 1000, max: 5 },
    revocation: { windowMs: 15 * 60 * 1000, max: 50 }
  },

  // Security constraints
  constraints: {
    maxRedirectUriLength: 2048,
    maxScopeLength: 1000,
    maxStateLength: 255,
    minStateLength: 8,
    maxClientIdLength: 100,
    maxTokenLength: 4096
  }
};

export default {
  rateLimiters: oauthRateLimiters,
  validator: OAuthInputValidator,
  headers: addOAuthSecurityHeaders,
  csrf: CSRFProtection,
  timing: TimingProtection,
  bruteForce: BruteForceProtection,
  audit: SecurityAuditLogger,
  tokens: TokenSecurity,
  config: securityConfig
};