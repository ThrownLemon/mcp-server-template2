import { Router, Request, Response } from 'express';
import { OAuthProvider } from './oauth.js';
import { logger } from '../utils/logger.js';
import * as url from 'url';
import { 
  oauthRateLimiters, 
  OAuthInputValidator, 
  addOAuthSecurityHeaders,
  BruteForceProtection,
  SecurityAuditLogger 
} from './security.js';

export interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    clientId: string;
    scopes: string[];
  };
}

// OAuth 2.0 Middleware
export function createOAuthMiddleware(oauthProvider: OAuthProvider) {
  return async (req: AuthenticatedRequest, res: Response, next: Function) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader) {
        return res.status(401).json({ 
          error: 'unauthorized',
          error_description: 'Authorization header required' 
        });
      }

      const [scheme, token] = authHeader.split(' ');
      
      if (scheme !== 'Bearer' || !token) {
        return res.status(401).json({ 
          error: 'invalid_token',
          error_description: 'Invalid authorization header format' 
        });
      }

      const validation = await oauthProvider.validateToken(token);
      
      if (!validation.valid) {
        return res.status(401).json({ 
          error: 'invalid_token',
          error_description: 'Invalid or expired access token' 
        });
      }

      // Add user info to request
      req.user = {
        userId: validation.payload.userId || validation.payload.sub,
        clientId: validation.payload.clientId || validation.payload.client_id,
        scopes: validation.payload.scopes || (validation.payload.scope ? validation.payload.scope.split(' ') : [])
      };

      return next();
    } catch (error) {
      logger.error('OAuth middleware error', error);
      return res.status(500).json({ 
        error: 'server_error',
        error_description: 'Internal server error' 
      });
    }
  };
}

// Scope validation middleware
export function requireScopes(requiredScopes: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: Function) => {
    if (!req.user) {
      res.status(401).json({ 
        error: 'unauthorized',
        error_description: 'Authentication required' 
      });
      return;
    }

    const hasAllScopes = requiredScopes.every(scope => 
      req.user!.scopes.includes(scope)
    );

    if (!hasAllScopes) {
      res.status(403).json({ 
        error: 'insufficient_scope',
        error_description: `Required scopes: ${requiredScopes.join(', ')}` 
      });
      return;
    }

    next();
  };
}

// OAuth 2.0 Routes
export function createOAuthRoutes(oauthProvider: OAuthProvider): Router {
  const router = Router();

  // Apply security headers to all OAuth routes
  router.use(addOAuthSecurityHeaders);

  // OpenID Connect Discovery
  router.get('/.well-known/openid_configuration', (req: Request, res: Response) => {
    try {
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const discovery = oauthProvider.getDiscoveryDocument(baseUrl);
      
      res.json(discovery);
      logger.info('Discovery document requested');
    } catch (error) {
      logger.error('Discovery document error', error);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // JWKS endpoint
  router.get('/oauth/jwks', (req: Request, res: Response) => {
    try {
      const jwks = oauthProvider.getJWKS();
      res.json(jwks);
      logger.info('JWKS requested');
    } catch (error) {
      logger.error('JWKS error', error);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // Authorization endpoint
  router.get('/oauth/authorize', 
    oauthRateLimiters.authorization,
    BruteForceProtection.checkBruteForce,
    (req: Request, res: Response) => {
    try {
      const {
        client_id,
        redirect_uri,
        scope,
        state,
        response_type,
        code_challenge,
        code_challenge_method
      } = req.query as Record<string, string>;

      // Enhanced input validation
      if (!client_id || !redirect_uri || !response_type) {
        SecurityAuditLogger.logSecurityViolation('missing_required_parameters', {
          provided: { client_id: !!client_id, redirect_uri: !!redirect_uri, response_type: !!response_type }
        }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters'
        });
      }

      // Validate client_id format
      if (!OAuthInputValidator.validateClientId(client_id)) {
        SecurityAuditLogger.logSecurityViolation('invalid_client_id_format', { client_id }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid client_id format'
        });
      }

      // Validate redirect_uri
      const redirectValidation = OAuthInputValidator.validateRedirectUri(redirect_uri);
      if (!redirectValidation.valid) {
        SecurityAuditLogger.logSecurityViolation('invalid_redirect_uri', {
          redirect_uri,
          reason: redirectValidation.reason
        }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: redirectValidation.reason || 'Invalid redirect_uri'
        });
      }

      // Validate scope if provided
      if (scope) {
        const scopeValidation = OAuthInputValidator.validateScope(scope);
        if (!scopeValidation.valid) {
          SecurityAuditLogger.logSecurityViolation('invalid_scope_format', {
            scope,
            reason: scopeValidation.reason
          }, req);
          
          return res.status(400).json({
            error: 'invalid_scope',
            error_description: scopeValidation.reason || 'Invalid scope format'
          });
        }
      }

      // Validate state parameter
      if (state && !OAuthInputValidator.validateState(state)) {
        SecurityAuditLogger.logSecurityViolation('invalid_state_format', { state }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid state parameter format'
        });
      }

      // Validate PKCE parameters if provided
      if (code_challenge && !OAuthInputValidator.validateCodeChallenge(code_challenge, code_challenge_method || 'plain')) {
        SecurityAuditLogger.logSecurityViolation('invalid_pkce_challenge', {
          code_challenge_method
        }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid code_challenge format'
        });
      }

      if (response_type !== 'code') {
        return res.status(400).json({
          error: 'unsupported_response_type',
          error_description: 'Only authorization code flow is supported'
        });
      }

      // Validate client
      const client = oauthProvider.getClient(client_id);
      if (!client) {
        SecurityAuditLogger.logSecurityViolation('unknown_client', { client_id }, req);
        BruteForceProtection.recordFailedAttempt(`${req.ip}-${client_id}`);
        
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Unknown client'
        });
      }

      // Validate redirect URI
      if (!client.redirectUris.includes(redirect_uri)) {
        SecurityAuditLogger.logSecurityViolation('unregistered_redirect_uri', {
          client_id,
          provided_uri: redirect_uri,
          registered_uris: client.redirectUris
        }, req);
        
        return res.status(400).json({
          error: 'invalid_redirect_uri',
          error_description: 'Redirect URI not registered for this client'
        });
      }

      // Parse and validate scopes
      const requestedScopes = scope ? scope.split(' ') : [];
      if (!oauthProvider.validateScopes(requestedScopes, client.scopes)) {
        const errorUrl = new URL(redirect_uri);
        errorUrl.searchParams.set('error', 'invalid_scope');
        errorUrl.searchParams.set('error_description', 'Invalid or unauthorized scopes');
        if (state) errorUrl.searchParams.set('state', state);
        return res.redirect(errorUrl.toString());
      }

      // In a real implementation, you would:
      // 1. Check if user is authenticated
      // 2. Show consent screen if needed
      // 3. Generate authorization code after consent
      
      // For demo purposes, we'll simulate user authentication and consent
      const userId = 'demo-user-123'; // In real implementation, get from session
      
      // Generate authorization code
      const authCode = oauthProvider.generateAuthorizationCode(
        client_id,
        redirect_uri,
        requestedScopes,
        userId,
        code_challenge,
        code_challenge_method
      );

      // Reset brute force protection on successful authorization
      BruteForceProtection.resetAttempts(`${req.ip}-${client_id}`);

      // Redirect back to client with authorization code
      const successUrl = new URL(redirect_uri);
      successUrl.searchParams.set('code', authCode);
      if (state) successUrl.searchParams.set('state', state);

      SecurityAuditLogger.logAuthEvent('authorization_granted', {
        clientId: client_id,
        userId,
        scopes: requestedScopes,
        hasPKCE: !!code_challenge
      }, req);

      res.redirect(successUrl.toString());
    } catch (error) {
      logger.error('Authorization endpoint error', error);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // Token endpoint
  router.post('/oauth/token', 
    oauthRateLimiters.token,
    BruteForceProtection.checkBruteForce,
    async (req: Request, res: Response) => {
    try {
      const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        refresh_token,
        code_verifier
      } = req.body;

      // Enhanced input validation
      if (!grant_type) {
        SecurityAuditLogger.logSecurityViolation('missing_grant_type', {}, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing grant_type parameter'
        });
      }

      // Validate authorization code format if provided
      if (code && !OAuthInputValidator.validateAuthorizationCode(code)) {
        SecurityAuditLogger.logSecurityViolation('invalid_authorization_code_format', {
          client_id
        }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid authorization code format'
        });
      }

      // Validate client_id format
      if (client_id && !OAuthInputValidator.validateClientId(client_id)) {
        SecurityAuditLogger.logSecurityViolation('invalid_client_id_format', {
          client_id
        }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid client_id format'
        });
      }

      // Validate refresh token format if provided
      if (refresh_token && !OAuthInputValidator.validateToken(refresh_token)) {
        SecurityAuditLogger.logSecurityViolation('invalid_refresh_token_format', {
          client_id
        }, req);
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid refresh token format'
        });
      }

      // Client authentication
      let clientAuth = client_id;
      let clientSecret = client_secret;

      // Support basic auth
      if (req.headers.authorization) {
        const authParts = req.headers.authorization.split(' ');
        const scheme = authParts[0];
        const credentials = authParts[1];
        if (scheme === 'Basic' && credentials && typeof credentials === 'string') {
          const [id, secret] = Buffer.from(credentials, 'base64').toString().split(':');
          clientAuth = id;
          clientSecret = secret;
        }
      }

      if (!clientAuth) {
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client authentication required'
        });
      }

      if (!oauthProvider.validateClient(clientAuth, clientSecret)) {
        SecurityAuditLogger.logSecurityViolation('invalid_client_credentials', {
          client_id: clientAuth
        }, req);
        BruteForceProtection.recordFailedAttempt(`${req.ip}-${clientAuth}`);
        
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials'
        });
      }

      // Reset brute force protection on successful client authentication
      BruteForceProtection.resetAttempts(`${req.ip}-${clientAuth}`);

      // Handle different grant types
      if (grant_type === 'authorization_code') {
        if (!code || !redirect_uri) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing required parameters for authorization code flow'
          });
        }

        try {
          const tokens = await oauthProvider.exchangeCodeForTokens(
            code,
            clientAuth,
            redirect_uri,
            code_verifier
          );

          SecurityAuditLogger.logAuthEvent('token_issued', {
            clientId: clientAuth,
            grantType: 'authorization_code',
            scopes: tokens.scope?.split(' ') || []
          }, req);

          return res.json(tokens);
        } catch (error) {
          logger.error('Token exchange error', error);
          SecurityAuditLogger.logSecurityViolation('token_exchange_failed', {
            client_id: clientAuth,
            error: error instanceof Error ? error.message : 'Unknown error'
          }, req);
          
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: error instanceof Error ? error.message : 'Token exchange failed'
          });
        }
      } else if (grant_type === 'refresh_token') {
        if (!refresh_token) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing refresh_token parameter'
          });
        }

        try {
          const tokens = await oauthProvider.refreshTokens(refresh_token, clientAuth);
          return res.json(tokens);
        } catch (error) {
          logger.error('Token refresh error', error);
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: error instanceof Error ? error.message : 'Token refresh failed'
          });
        }
      } else {
        return res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: 'Supported grant types: authorization_code, refresh_token'
        });
      }
    } catch (error) {
      logger.error('Token endpoint error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Token revocation endpoint
  router.post('/oauth/revoke', async (req: Request, res: Response) => {
    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing token parameter'
        });
      }

      // Client authentication (optional for revocation)
      let clientAuth;
      if (req.headers.authorization) {
        const authParts = req.headers.authorization.split(' ');
        const scheme = authParts[0];
        const credentials = authParts[1];
        if (scheme === 'Basic' && credentials && typeof credentials === 'string') {
          try {
            const decoded = Buffer.from(credentials, 'base64').toString();
            const parts = decoded.split(':');
            if (parts.length >= 2) {
              const id = parts[0];
              const secret = parts[1];
              if (id && secret && oauthProvider.validateClient(id, secret)) {
                clientAuth = id;
              }
            }
          } catch (error) {
            logger.warn('Invalid basic auth credentials format');
          }
        }
      }

      const revoked = await oauthProvider.revokeToken(token);
      
      if (revoked) {
        logger.info('Token revoked successfully', { clientId: clientAuth });
      } else {
        logger.warn('Token revocation failed - token not found', { clientId: clientAuth });
      }

      // Always return 200 for security (don't leak token existence)
      return res.status(200).send('');
    } catch (error) {
      logger.error('Revocation endpoint error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // UserInfo endpoint (OpenID Connect)
  router.get('/oauth/userinfo', createOAuthMiddleware(oauthProvider), requireScopes(['openid']), (req: AuthenticatedRequest, res: Response) => {
    try {
      // In a real implementation, fetch user data from database
      const userInfo = {
        sub: req.user!.userId,
        name: 'Demo User',
        email: 'demo@example.com',
        email_verified: true
      };

      res.json(userInfo);
      logger.info('UserInfo requested', { userId: req.user!.userId });
    } catch (error) {
      logger.error('UserInfo endpoint error', error);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // OAuth statistics (protected endpoint)
  router.get('/oauth/stats', createOAuthMiddleware(oauthProvider), requireScopes(['admin']), (req: AuthenticatedRequest, res: Response) => {
    try {
      const stats = oauthProvider.getStats();
      res.json(stats);
      logger.info('OAuth stats requested', { userId: req.user!.userId });
    } catch (error) {
      logger.error('Stats endpoint error', error);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // Client Management Endpoints (Admin only)
  
  // List all registered clients
  router.get('/oauth/clients', 
    oauthRateLimiters.clientManagement,
    createOAuthMiddleware(oauthProvider), 
    requireScopes(['admin']), 
    (req: AuthenticatedRequest, res: Response) => {
    try {
      const clients = oauthProvider.getAllClients().map(client => ({
        clientId: client.clientId,
        name: client.name,
        type: client.type,
        redirectUris: client.redirectUris,
        scopes: client.scopes,
        grantTypes: client.grantTypes
        // Don't expose client secrets
      }));
      
      SecurityAuditLogger.logAdminAction('client_list_accessed', {
        adminUser: req.user!.userId,
        clientCount: clients.length
      }, req);

      return res.json({ clients });
    } catch (error) {
      logger.error('Client list error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Get specific client details
  router.get('/oauth/clients/:clientId', 
    oauthRateLimiters.clientManagement,
    createOAuthMiddleware(oauthProvider), 
    requireScopes(['admin']), 
    (req: AuthenticatedRequest, res: Response) => {
    try {
      const { clientId } = req.params;
      
      if (!clientId) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Client ID is required'
        });
      }
      
      const client = oauthProvider.getClient(clientId);
      
      if (!client) {
        return res.status(404).json({
          error: 'client_not_found',
          error_description: 'Client not found'
        });
      }

      return res.json({
        clientId: client.clientId,
        name: client.name,
        type: client.type,
        redirectUris: client.redirectUris,
        scopes: client.scopes,
        grantTypes: client.grantTypes
        // Don't expose client secret
      });
    } catch (error) {
      logger.error('Client details error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Dynamic client registration
  router.post('/oauth/clients', 
    oauthRateLimiters.clientManagement,
    createOAuthMiddleware(oauthProvider), 
    requireScopes(['admin']), 
    (req: AuthenticatedRequest, res: Response) => {
    try {
      const {
        client_name,
        redirect_uris,
        grant_types,
        response_types,
        scope,
        client_type
      } = req.body;

      if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirect_uris is required and must be a non-empty array'
        });
      }

      // Validate scopes if provided
      if (scope) {
        const scopes = scope.split(' ');
        const validation = oauthProvider.validateScopeStrings(scopes);
        if (!validation.valid) {
          return res.status(400).json({
            error: 'invalid_scope',
            error_description: `Invalid scopes: ${validation.invalidScopes.join(', ')}`
          });
        }
      }

      const client = oauthProvider.registerClientDynamic({
        client_name,
        redirect_uris,
        grant_types,
        response_types,
        scope,
        client_type
      });

      return res.status(201).json({
        client_id: client.clientId,
        client_secret: client.type === 'confidential' ? client.clientSecret : undefined,
        client_name: client.name,
        client_type: client.type,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        scope: client.scopes.join(' ')
      });
    } catch (error) {
      logger.error('Client registration error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Update client
  router.put('/oauth/clients/:clientId', 
    oauthRateLimiters.clientManagement,
    createOAuthMiddleware(oauthProvider), 
    requireScopes(['admin']), 
    (req: AuthenticatedRequest, res: Response) => {
    try {
      const { clientId } = req.params;
      const { name, redirect_uris, scopes, grant_types } = req.body;

      if (!clientId) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Client ID is required'
        });
      }

      if (!oauthProvider.getClient(clientId)) {
        return res.status(404).json({
          error: 'client_not_found',
          error_description: 'Client not found'
        });
      }

      const updates: any = {};
      if (name) updates.name = name;
      if (redirect_uris) updates.redirectUris = redirect_uris;
      if (scopes) {
        // Validate scopes
        const validation = oauthProvider.validateScopeStrings(scopes);
        if (!validation.valid) {
          return res.status(400).json({
            error: 'invalid_scope',
            error_description: `Invalid scopes: ${validation.invalidScopes.join(', ')}`
          });
        }
        updates.scopes = scopes;
      }
      if (grant_types) updates.grantTypes = grant_types;

      const success = oauthProvider.updateClient(clientId, updates);
      if (!success) {
        return res.status(500).json({ error: 'update_failed' });
      }

      return res.json({ message: 'Client updated successfully' });
    } catch (error) {
      logger.error('Client update error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Delete client
  router.delete('/oauth/clients/:clientId', createOAuthMiddleware(oauthProvider), requireScopes(['admin']), (req: AuthenticatedRequest, res: Response) => {
    try {
      const { clientId } = req.params;

      if (!clientId) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Client ID is required'
        });
      }

      const success = oauthProvider.deleteClient(clientId);
      if (!success) {
        return res.status(404).json({
          error: 'client_not_found',
          error_description: 'Client not found'
        });
      }

      return res.json({ message: 'Client deleted successfully' });
    } catch (error) {
      logger.error('Client deletion error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Scope information endpoint
  router.get('/oauth/scopes', (req: Request, res: Response) => {
    try {
      const supportedScopes = oauthProvider.getSupportedScopes();
      return res.json({ scopes: supportedScopes });
    } catch (error) {
      logger.error('Scopes endpoint error', error);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
}