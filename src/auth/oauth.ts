import type { OAuthConfig, OAuthTokens } from '../types/index.js';
import { logger } from '../utils/logger.js';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

// OAuth 2.0 Client Management
export interface OAuthClient {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scopes: string[];
  grantTypes: string[];
  name: string;
  type: 'confidential' | 'public';
}

// OAuth 2.0 Authorization Code
export interface AuthorizationCode {
  code: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  userId: string;
  expiresAt: Date;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

// Access Token
export interface AccessToken {
  token: string;
  clientId: string;
  userId: string;
  scopes: string[];
  expiresAt: Date;
}

// Refresh Token
export interface RefreshToken {
  token: string;
  clientId: string;
  userId: string;
  scopes: string[];
  expiresAt: Date;
}

// In-memory storage (in production, use database)
const clients = new Map<string, OAuthClient>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, AccessToken>();
const refreshTokens = new Map<string, RefreshToken>();

// OAuth 2.0 Provider Implementation
export class OAuthProvider {
  private jwtSecret: string;

  constructor(private config: OAuthConfig) {
    this.jwtSecret = config.clientSecret + '_jwt_secret';
    logger.info('OAuth 2.0 provider initialized', { 
      clientId: config.clientId,
      scopes: config.scopes 
    });

    // Register the default client
    this.registerClient({
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUris: [config.redirectUri],
      scopes: config.scopes,
      grantTypes: ['authorization_code', 'refresh_token'],
      name: 'MCP Server Template',
      type: 'confidential'
    });
  }

  // Client Management
  registerClient(client: OAuthClient): void {
    clients.set(client.clientId, client);
    logger.info('OAuth client registered', { clientId: client.clientId, name: client.name });
  }

  getClient(clientId: string): OAuthClient | undefined {
    return clients.get(clientId);
  }

  validateClient(clientId: string, clientSecret?: string): boolean {
    const client = clients.get(clientId);
    if (!client) return false;
    
    // For public clients, no secret validation
    if (client.type === 'public') return true;
    
    // For confidential clients, validate secret
    return client.clientSecret === clientSecret;
  }

  // Enhanced Client Management
  getAllClients(): OAuthClient[] {
    return Array.from(clients.values());
  }

  updateClient(clientId: string, updates: Partial<OAuthClient>): boolean {
    const client = clients.get(clientId);
    if (!client) return false;

    const updatedClient = { ...client, ...updates, clientId }; // Preserve clientId
    clients.set(clientId, updatedClient);
    logger.info('OAuth client updated', { clientId, updates });
    return true;
  }

  deleteClient(clientId: string): boolean {
    const client = clients.get(clientId);
    if (!client) return false;

    // Revoke all tokens for this client
    this.revokeAllClientTokens(clientId);
    
    clients.delete(clientId);
    logger.info('OAuth client deleted', { clientId, name: client.name });
    return true;
  }

  // Dynamic Client Registration (RFC 7591)
  registerClientDynamic(registration: {
    client_name?: string;
    redirect_uris: string[];
    grant_types?: string[];
    response_types?: string[];
    scope?: string;
    client_type?: 'confidential' | 'public';
  }): OAuthClient {
    const clientId = crypto.randomBytes(16).toString('hex');
    const clientSecret = registration.client_type === 'public' 
      ? undefined 
      : crypto.randomBytes(32).toString('base64url');

    const client: OAuthClient = {
      clientId,
      clientSecret: clientSecret || '',
      redirectUris: registration.redirect_uris,
      scopes: registration.scope ? registration.scope.split(' ') : ['read'],
      grantTypes: registration.grant_types || ['authorization_code', 'refresh_token'],
      name: registration.client_name || `Dynamic Client ${clientId}`,
      type: registration.client_type || 'confidential'
    };

    this.registerClient(client);
    return client;
  }

  // Authorization Code Flow
  generateAuthorizationCode(
    clientId: string, 
    redirectUri: string, 
    scopes: string[], 
    userId: string,
    codeChallenge?: string,
    codeChallengeMethod?: string
  ): string {
    const code = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    authorizationCodes.set(code, {
      code,
      clientId,
      redirectUri,
      scopes,
      userId,
      expiresAt,
      codeChallenge,
      codeChallengeMethod
    });

    // Clean up expired codes
    this.cleanupExpiredCodes();

    logger.info('Authorization code generated', { 
      clientId, 
      userId, 
      scopes,
      codeChallenge: !!codeChallenge 
    });

    return code;
  }

  // Token Exchange
  async exchangeCodeForTokens(
    code: string, 
    clientId: string, 
    redirectUri: string,
    codeVerifier?: string
  ): Promise<OAuthTokens> {
    const authCode = authorizationCodes.get(code);
    
    if (!authCode) {
      throw new Error('Invalid authorization code');
    }

    if (authCode.expiresAt < new Date()) {
      authorizationCodes.delete(code);
      throw new Error('Authorization code expired');
    }

    if (authCode.clientId !== clientId) {
      throw new Error('Client mismatch');
    }

    if (authCode.redirectUri !== redirectUri) {
      throw new Error('Redirect URI mismatch');
    }

    // PKCE validation
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        throw new Error('Code verifier required for PKCE');
      }

      const challenge = authCode.codeChallengeMethod === 'S256'
        ? crypto.createHash('sha256').update(codeVerifier).digest('base64url')
        : codeVerifier;

      if (challenge !== authCode.codeChallenge) {
        throw new Error('Invalid code verifier');
      }
    }

    // Generate tokens
    const accessToken = this.generateAccessToken(clientId, authCode.userId, authCode.scopes);
    const refreshToken = this.generateRefreshToken(clientId, authCode.userId, authCode.scopes);

    // Clean up authorization code
    authorizationCodes.delete(code);

    const tokens: OAuthTokens = {
      accessToken: accessToken.token,
      refreshToken: refreshToken.token,
      tokenType: 'Bearer',
      expiresIn: Math.floor((accessToken.expiresAt.getTime() - Date.now()) / 1000),
      scope: authCode.scopes.join(' ')
    };

    // Generate ID token if openid scope is present
    if (authCode.scopes.includes('openid')) {
      tokens.idToken = this.generateIdToken(authCode.userId, clientId, authCode.scopes);
    }

    logger.info('Tokens exchanged successfully', { 
      clientId, 
      userId: authCode.userId,
      scopes: authCode.scopes 
    });

    return tokens;
  }

  // Token Generation
  generateAccessToken(clientId: string, userId: string, scopes: string[]): AccessToken {
    const token = jwt.sign(
      {
        sub: userId,
        client_id: clientId,
        scope: scopes.join(' '),
        iss: this.config.issuer,
        aud: clientId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
      },
      this.jwtSecret,
      { algorithm: 'HS256' }
    );

    const accessToken: AccessToken = {
      token,
      clientId,
      userId,
      scopes,
      expiresAt: new Date(Date.now() + 3600 * 1000) // 1 hour
    };

    accessTokens.set(token, accessToken);
    return accessToken;
  }

  generateRefreshToken(clientId: string, userId: string, scopes: string[]): RefreshToken {
    const token = crypto.randomBytes(32).toString('base64url');
    
    const refreshToken: RefreshToken = {
      token,
      clientId,
      userId,
      scopes,
      expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000) // 30 days
    };

    refreshTokens.set(token, refreshToken);
    return refreshToken;
  }

  generateIdToken(userId: string, clientId: string, scopes: string[]): string {
    return jwt.sign(
      {
        sub: userId,
        aud: clientId,
        iss: this.config.issuer,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
        auth_time: Math.floor(Date.now() / 1000),
        scope: scopes.join(' ')
      },
      this.jwtSecret,
      { algorithm: 'HS256' }
    );
  }

  // Token Validation
  async validateToken(token: string): Promise<{ valid: boolean; payload?: any }> {
    try {
      // First check if it's in our access tokens store
      const storedToken = accessTokens.get(token);
      if (storedToken) {
        if (storedToken.expiresAt < new Date()) {
          accessTokens.delete(token);
          return { valid: false };
        }
        return { 
          valid: true, 
          payload: {
            userId: storedToken.userId,
            clientId: storedToken.clientId,
            scopes: storedToken.scopes
          }
        };
      }

      // Try to verify as JWT
      const payload = jwt.verify(token, this.jwtSecret) as any;
      return { valid: true, payload };
    } catch (error) {
      logger.warn('Token validation failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      return { valid: false };
    }
  }

  // Refresh Token Flow
  async refreshTokens(refreshTokenString: string, clientId: string): Promise<OAuthTokens> {
    const refreshTokenData = refreshTokens.get(refreshTokenString);
    
    if (!refreshTokenData) {
      throw new Error('Invalid refresh token');
    }

    if (refreshTokenData.expiresAt < new Date()) {
      refreshTokens.delete(refreshTokenString);
      throw new Error('Refresh token expired');
    }

    if (refreshTokenData.clientId !== clientId) {
      throw new Error('Client mismatch');
    }

    // Generate new tokens
    const newAccessToken = this.generateAccessToken(
      clientId, 
      refreshTokenData.userId, 
      refreshTokenData.scopes
    );

    const newRefreshToken = this.generateRefreshToken(
      clientId,
      refreshTokenData.userId,
      refreshTokenData.scopes
    );

    // Remove old refresh token
    refreshTokens.delete(refreshTokenString);

    const tokens: OAuthTokens = {
      accessToken: newAccessToken.token,
      refreshToken: newRefreshToken.token,
      tokenType: 'Bearer',
      expiresIn: Math.floor((newAccessToken.expiresAt.getTime() - Date.now()) / 1000),
      scope: refreshTokenData.scopes.join(' ')
    };

    // Generate new ID token if openid scope is present
    if (refreshTokenData.scopes.includes('openid')) {
      tokens.idToken = this.generateIdToken(refreshTokenData.userId, clientId, refreshTokenData.scopes);
    }

    logger.info('Tokens refreshed successfully', { 
      clientId, 
      userId: refreshTokenData.userId,
      scopes: refreshTokenData.scopes 
    });

    return tokens;
  }

  // Token Revocation
  async revokeToken(token: string): Promise<boolean> {
    try {
      // Try to revoke as access token
      if (accessTokens.has(token)) {
        accessTokens.delete(token);
        logger.info('Access token revoked');
        return true;
      }

      // Try to revoke as refresh token
      if (refreshTokens.has(token)) {
        refreshTokens.delete(token);
        logger.info('Refresh token revoked');
        return true;
      }

      return false;
    } catch (error) {
      logger.error('Token revocation failed', error);
      return false;
    }
  }

  // Revoke all tokens for a specific client
  revokeAllClientTokens(clientId: string): number {
    let revokedCount = 0;

    // Revoke access tokens
    for (const [token, tokenData] of accessTokens.entries()) {
      if (tokenData.clientId === clientId) {
        accessTokens.delete(token);
        revokedCount++;
      }
    }

    // Revoke refresh tokens
    for (const [token, tokenData] of refreshTokens.entries()) {
      if (tokenData.clientId === clientId) {
        refreshTokens.delete(token);
        revokedCount++;
      }
    }

    // Revoke authorization codes
    for (const [code, codeData] of authorizationCodes.entries()) {
      if (codeData.clientId === clientId) {
        authorizationCodes.delete(code);
        revokedCount++;
      }
    }

    logger.info('All tokens revoked for client', { clientId, revokedCount });
    return revokedCount;
  }

  // Scope Validation and Management
  validateScopes(requestedScopes: string[], clientScopes: string[]): boolean {
    return requestedScopes.every(scope => clientScopes.includes(scope));
  }

  // Standard OAuth 2.0 scopes with descriptions
  getSupportedScopes(): Record<string, string> {
    return {
      'read': 'Read access to resources',
      'write': 'Write access to resources',
      'delete': 'Delete access to resources',
      'admin': 'Administrative access to all resources',
      'openid': 'OpenID Connect authentication',
      'profile': 'Access to user profile information',
      'email': 'Access to user email address',
      'offline_access': 'Refresh token access for offline operations'
    };
  }

  // Validate scope format and existence
  validateScopeStrings(scopes: string[]): { valid: boolean; invalidScopes: string[] } {
    const supportedScopes = Object.keys(this.getSupportedScopes());
    const invalidScopes = scopes.filter(scope => !supportedScopes.includes(scope));
    
    return {
      valid: invalidScopes.length === 0,
      invalidScopes
    };
  }

  // Get effective scopes (intersection of requested and allowed)
  getEffectiveScopes(requestedScopes: string[], clientScopes: string[]): string[] {
    return requestedScopes.filter(scope => clientScopes.includes(scope));
  }

  // Check if a scope hierarchy is satisfied (e.g., admin includes read/write)
  checkScopeHierarchy(userScopes: string[], requiredScopes: string[]): boolean {
    // Admin scope includes all other scopes
    if (userScopes.includes('admin')) {
      return true;
    }

    // Write scope includes read
    const effectiveScopes = [...userScopes];
    if (userScopes.includes('write') && !userScopes.includes('read')) {
      effectiveScopes.push('read');
    }

    return requiredScopes.every(required => effectiveScopes.includes(required));
  }

  // PKCE Support
  generateCodeChallenge(codeVerifier: string, method: 'plain' | 'S256' = 'S256'): string {
    if (method === 'plain') {
      return codeVerifier;
    }
    return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  }

  generateCodeVerifier(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  // Utility Methods
  private cleanupExpiredCodes(): void {
    const now = new Date();
    for (const [code, authCode] of authorizationCodes.entries()) {
      if (authCode.expiresAt < now) {
        authorizationCodes.delete(code);
      }
    }
  }

  // Get OpenID Connect Discovery Document
  getDiscoveryDocument(baseUrl: string): any {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${baseUrl}/auth/oauth/authorize`,
      token_endpoint: `${baseUrl}/auth/oauth/token`,
      revocation_endpoint: `${baseUrl}/auth/oauth/revoke`,
      userinfo_endpoint: `${baseUrl}/auth/oauth/userinfo`,
      jwks_uri: `${baseUrl}/auth/oauth/jwks`,
      scopes_supported: this.config.scopes,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      code_challenge_methods_supported: ['plain', 'S256'],
      subject_types_supported: ['public']
    };
  }

  // Get JWKS (JSON Web Key Set)
  getJWKS(): any {
    // In production, use proper key management
    const key = crypto.createHash('sha256').update(this.jwtSecret).digest('hex');
    return {
      keys: [
        {
          kty: 'oct',
          use: 'sig',
          alg: 'HS256',
          kid: 'default',
          k: Buffer.from(key).toString('base64url')
        }
      ]
    };
  }

  // Statistics
  getStats(): any {
    return {
      clients: clients.size,
      activeCodes: authorizationCodes.size,
      activeAccessTokens: accessTokens.size,
      activeRefreshTokens: refreshTokens.size
    };
  }
}