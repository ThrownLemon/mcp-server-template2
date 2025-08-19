import { OAuthProvider, OAuthClient } from '../auth/oauth.js';
import { logger } from '../utils/logger.js';

/**
 * OAuth 2.0 Provider Examples and Configuration Patterns
 * 
 * This file demonstrates various OAuth 2.0 configurations and usage patterns
 * for different scenarios and security requirements.
 */

// Example OAuth configurations for different environments
export const oauthConfigurations = {
  // Development environment configuration
  development: {
    clientId: 'mcp-dev-client',
    clientSecret: 'dev-secret-key-change-in-production',
    redirectUri: 'http://localhost:3000/auth/callback',
    issuer: 'http://localhost:8181',
    scopes: ['read', 'write', 'admin', 'openid', 'profile', 'email']
  },

  // Production environment configuration
  production: {
    clientId: process.env.OAUTH_CLIENT_ID || 'mcp-prod-client',
    clientSecret: process.env.OAUTH_CLIENT_SECRET || 'production-secret-change-me',
    redirectUri: process.env.OAUTH_REDIRECT_URI || 'https://your-app.com/auth/callback',
    issuer: process.env.OAUTH_ISSUER || 'https://your-auth-server.com',
    scopes: ['read', 'write', 'openid', 'profile', 'email'] // Note: admin not included by default
  },

  // Testing environment configuration
  testing: {
    clientId: 'mcp-test-client',
    clientSecret: 'test-secret',
    redirectUri: 'http://localhost:3001/auth/callback',
    issuer: 'http://localhost:8182',
    scopes: ['read', 'write', 'openid']
  }
};

// Example client configurations for different application types
export const exampleClients: Record<string, OAuthClient> = {
  // Web application (confidential client)
  webApp: {
    clientId: 'web-app-client',
    clientSecret: 'web-app-secret-key',
    redirectUris: [
      'https://myapp.com/auth/callback',
      'https://myapp.com/auth/silent'
    ],
    scopes: ['read', 'write', 'openid', 'profile', 'email'],
    grantTypes: ['authorization_code', 'refresh_token'],
    name: 'My Web Application',
    type: 'confidential'
  },

  // Single Page Application (public client)
  spa: {
    clientId: 'spa-client',
    clientSecret: '', // Public clients don't have secrets
    redirectUris: [
      'https://myapp.com/callback',
      'http://localhost:3000/callback'
    ],
    scopes: ['read', 'openid', 'profile'],
    grantTypes: ['authorization_code'], // Only auth code with PKCE
    name: 'My Single Page App',
    type: 'public'
  },

  // Mobile application (public client with custom scheme)
  mobile: {
    clientId: 'mobile-app-client',
    clientSecret: '',
    redirectUris: [
      'myapp://auth/callback',
      'com.mycompany.myapp://callback'
    ],
    scopes: ['read', 'write', 'offline_access'],
    grantTypes: ['authorization_code', 'refresh_token'],
    name: 'My Mobile App',
    type: 'public'
  },

  // API client (confidential client for server-to-server)
  apiClient: {
    clientId: 'api-service-client',
    clientSecret: 'api-service-secret-key',
    redirectUris: [], // No redirect for client credentials flow
    scopes: ['read', 'write', 'admin'],
    grantTypes: ['client_credentials'],
    name: 'API Service Client',
    type: 'confidential'
  },

  // Admin dashboard (confidential client with high privileges)
  adminDashboard: {
    clientId: 'admin-dashboard',
    clientSecret: 'admin-dashboard-secret',
    redirectUris: [
      'https://admin.myapp.com/auth/callback'
    ],
    scopes: ['admin', 'read', 'write', 'delete', 'openid', 'profile'],
    grantTypes: ['authorization_code', 'refresh_token'],
    name: 'Admin Dashboard',
    type: 'confidential'
  }
};

/**
 * Creates an OAuth provider with example configurations
 */
export function createExampleOAuthProvider(environment: 'development' | 'production' | 'testing' = 'development'): OAuthProvider {
  const config = oauthConfigurations[environment];
  const provider = new OAuthProvider(config);

  logger.info('Created OAuth provider for environment', { 
    environment, 
    issuer: config.issuer,
    scopes: config.scopes 
  });

  return provider;
}

/**
 * Registers example clients with the OAuth provider
 */
export function registerExampleClients(provider: OAuthProvider): void {
  Object.entries(exampleClients).forEach(([key, client]) => {
    try {
      provider.registerClient(client);
      logger.info('Registered example OAuth client', { 
        type: key, 
        clientId: client.clientId,
        clientType: client.type 
      });
    } catch (error) {
      logger.error('Failed to register example client', { 
        type: key, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      });
    }
  });
}

/**
 * OAuth 2.0 Flow Examples
 * 
 * These examples demonstrate how to implement different OAuth flows
 */

// Authorization Code Flow Example (for web applications)
export const authorizationCodeFlowExample = {
  // Step 1: Generate authorization URL
  generateAuthUrl: (provider: OAuthProvider, clientId: string, redirectUri: string, scopes: string[]) => {
    const state = provider.generateCodeVerifier(); // Use as state for simplicity
    const codeVerifier = provider.generateCodeVerifier();
    const codeChallenge = provider.generateCodeChallenge(codeVerifier, 'S256');

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });

    return {
      url: `${provider.getDiscoveryDocument('http://localhost:8181').authorization_endpoint}?${params.toString()}`,
      codeVerifier,
      state
    };
  },

  // Step 2: Exchange authorization code for tokens
  exchangeCode: async (provider: OAuthProvider, code: string, clientId: string, redirectUri: string, codeVerifier: string) => {
    try {
      const tokens = await provider.exchangeCodeForTokens(code, clientId, redirectUri, codeVerifier);
      logger.info('Successfully exchanged authorization code for tokens');
      return tokens;
    } catch (error) {
      logger.error('Failed to exchange authorization code', error);
      throw error;
    }
  }
};

// Client Credentials Flow Example (for server-to-server communication)
export const clientCredentialsFlowExample = {
  // Note: This would typically be implemented as a separate grant type
  // For demo purposes, we show how it would be structured
  authenticate: async (provider: OAuthProvider, clientId: string, clientSecret: string, scopes: string[]) => {
    // In a real implementation, this would be a separate method
    logger.info('Client credentials flow would be implemented here', {
      clientId,
      scopes
    });
    
    // For demonstration, generate a token directly
    const accessToken = provider.generateAccessToken(clientId, 'system', scopes);
    return {
      accessToken: accessToken.token,
      tokenType: 'Bearer',
      expiresIn: Math.floor((accessToken.expiresAt.getTime() - Date.now()) / 1000),
      scope: scopes.join(' ')
    };
  }
};

/**
 * Security Best Practices Examples
 */
export const securityExamples = {
  // PKCE (Proof Key for Code Exchange) example
  pkceFlow: {
    description: 'PKCE adds security for public clients by using dynamic secrets',
    implementation: (provider: OAuthProvider) => {
      const codeVerifier = provider.generateCodeVerifier();
      const codeChallenge = provider.generateCodeChallenge(codeVerifier, 'S256');
      
      return {
        codeVerifier,  // Keep this secret on the client
        codeChallenge, // Send this in the authorization request
        codeChallengeMethod: 'S256'
      };
    }
  },

  // State parameter example
  stateParameter: {
    description: 'State parameter prevents CSRF attacks',
    implementation: () => {
      // Generate a random state value
      const state = Math.random().toString(36).substring(2, 15) + 
                   Math.random().toString(36).substring(2, 15);
      
      // Store this state in session/local storage
      // Verify it matches when the callback is received
      return state;
    }
  },

  // Scope validation example
  scopeValidation: {
    description: 'Always validate requested scopes against client permissions',
    implementation: (provider: OAuthProvider, requestedScopes: string[], clientId: string) => {
      const client = provider.getClient(clientId);
      if (!client) {
        throw new Error('Unknown client');
      }

      const validation = provider.validateScopes(requestedScopes, client.scopes);
      if (!validation) {
        throw new Error('Insufficient permissions for requested scopes');
      }

      return provider.getEffectiveScopes(requestedScopes, client.scopes);
    }
  }
};

/**
 * Common OAuth Error Scenarios and Handling
 */
export const errorHandlingExamples = {
  // Invalid client error
  invalidClient: {
    error: 'invalid_client',
    error_description: 'Client authentication failed',
    status: 401
  },

  // Invalid grant error
  invalidGrant: {
    error: 'invalid_grant',
    error_description: 'The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI',
    status: 400
  },

  // Invalid scope error
  invalidScope: {
    error: 'invalid_scope',
    error_description: 'The requested scope is invalid, unknown, or malformed',
    status: 400
  },

  // Server error
  serverError: {
    error: 'server_error',
    error_description: 'The authorization server encountered an unexpected condition',
    status: 500
  }
};

/**
 * OAuth Configuration Validator
 */
export class OAuthConfigValidator {
  static validateConfiguration(config: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Required fields
    if (!config.clientId) errors.push('clientId is required');
    if (!config.clientSecret) errors.push('clientSecret is required');
    if (!config.redirectUri) errors.push('redirectUri is required');
    if (!config.issuer) errors.push('issuer is required');
    if (!config.scopes || !Array.isArray(config.scopes)) {
      errors.push('scopes must be an array');
    }

    // URL validation
    try {
      new URL(config.redirectUri);
    } catch {
      errors.push('redirectUri must be a valid URL');
    }

    try {
      new URL(config.issuer);
    } catch {
      errors.push('issuer must be a valid URL');
    }

    // Security checks
    if (config.clientSecret.length < 32) {
      errors.push('clientSecret should be at least 32 characters long');
    }

    if (config.issuer.startsWith('http:') && !config.issuer.includes('localhost')) {
      errors.push('issuer should use HTTPS in production');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  static validateClient(client: OAuthClient): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Required fields
    if (!client.clientId) errors.push('clientId is required');
    if (client.type === 'confidential' && !client.clientSecret) {
      errors.push('clientSecret is required for confidential clients');
    }
    if (!client.redirectUris || client.redirectUris.length === 0) {
      errors.push('at least one redirectUri is required');
    }

    // Validate redirect URIs
    client.redirectUris.forEach((uri, index) => {
      try {
        const url = new URL(uri);
        // Custom schemes are allowed for mobile apps
        if (!['http:', 'https:', 'com.', 'myapp:'].some(scheme => uri.startsWith(scheme))) {
          errors.push(`redirectUri[${index}] uses unsupported scheme`);
        }
      } catch {
        errors.push(`redirectUri[${index}] is not a valid URI`);
      }
    });

    // Validate grant types
    const validGrantTypes = ['authorization_code', 'refresh_token', 'client_credentials'];
    client.grantTypes.forEach(grantType => {
      if (!validGrantTypes.includes(grantType)) {
        errors.push(`invalid grant type: ${grantType}`);
      }
    });

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

/**
 * Usage Examples and Documentation
 */
export const usageExamples = {
  // Basic setup
  basicSetup: () => {
    const provider = createExampleOAuthProvider('development');
    registerExampleClients(provider);
    return provider;
  },

  // Generate authorization URL for web app
  webAppAuth: (provider: OAuthProvider) => {
    return authorizationCodeFlowExample.generateAuthUrl(
      provider,
      'web-app-client',
      'https://myapp.com/auth/callback',
      ['read', 'write', 'openid', 'profile']
    );
  },

  // Mobile app with PKCE
  mobileAppAuth: (provider: OAuthProvider) => {
    return authorizationCodeFlowExample.generateAuthUrl(
      provider,
      'mobile-app-client',
      'myapp://auth/callback',
      ['read', 'write', 'offline_access']
    );
  }
};

// Export everything for easy access
export default {
  configurations: oauthConfigurations,
  clients: exampleClients,
  flows: {
    authorizationCode: authorizationCodeFlowExample,
    clientCredentials: clientCredentialsFlowExample
  },
  security: securityExamples,
  errors: errorHandlingExamples,
  validator: OAuthConfigValidator,
  usage: usageExamples,
  createProvider: createExampleOAuthProvider,
  registerClients: registerExampleClients
};