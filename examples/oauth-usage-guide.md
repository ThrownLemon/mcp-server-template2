# OAuth 2.0 Usage Guide

This guide demonstrates how to use the OAuth 2.0 functionality implemented in the MCP Server Template.

## Quick Start

### 1. Basic Server Setup

The HTTP transport automatically includes OAuth 2.0 endpoints. Start the server:

```bash
npm run build
node dist/http-server.js
```

The server will be available at `http://localhost:8181` with the following OAuth endpoints:

- **Authorization**: `GET /oauth/authorize`
- **Token Exchange**: `POST /oauth/token`
- **Token Revocation**: `POST /oauth/revoke`
- **User Info**: `GET /oauth/userinfo`
- **JWKS**: `GET /oauth/jwks`
- **Discovery**: `GET /.well-known/openid_configuration`

### 2. Client Registration

#### Automatic Registration (Development)
The server automatically registers a default client on startup:
- **Client ID**: `mcp-template-client`
- **Client Secret**: `mcp-template-secret-key`
- **Redirect URI**: `http://localhost:3000/auth/callback`

#### Dynamic Client Registration (Admin Required)
Create new clients via the API:

```bash
# Get admin access token first (see authentication section)
curl -X POST http://localhost:8181/oauth/clients \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Web App",
    "redirect_uris": ["https://myapp.com/callback"],
    "client_type": "confidential",
    "scope": "read write openid"
  }'
```

### 3. OAuth 2.0 Flows

#### Authorization Code Flow (Web Applications)

**Step 1: Generate Authorization URL**

```bash
# Navigate user to this URL
https://localhost:8181/oauth/authorize?response_type=code&client_id=mcp-template-client&redirect_uri=http://localhost:3000/auth/callback&scope=read%20write%20openid&state=random-state-value&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

**Step 2: Handle Authorization Callback**

The user will be redirected to your `redirect_uri` with an authorization code:
```
http://localhost:3000/auth/callback?code=AUTHORIZATION_CODE&state=random-state-value
```

**Step 3: Exchange Code for Tokens**

```bash
curl -X POST http://localhost:8181/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=http://localhost:3000/auth/callback&client_id=mcp-template-client&client_secret=mcp-template-secret-key&code_verifier=CODE_VERIFIER"
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "REFRESH_TOKEN",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write openid"
}
```

### 4. Using Access Tokens

Include the access token in API requests:

```bash
curl -X GET http://localhost:8181/oauth/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 5. Token Refresh

When your access token expires, use the refresh token:

```bash
curl -X POST http://localhost:8181/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=mcp-template-client&client_secret=mcp-template-secret-key"
```

## Client Types and Use Cases

### Web Applications (Confidential Clients)

Best for server-side applications that can securely store client secrets.

```typescript
const client = {
  clientId: 'web-app-client',
  clientSecret: 'secure-secret-key',
  redirectUris: ['https://myapp.com/auth/callback'],
  scopes: ['read', 'write', 'openid', 'profile'],
  type: 'confidential'
};
```

**Security Features:**
- Client secret authentication
- Authorization code flow with PKCE
- Refresh tokens for long-term access

### Single Page Applications (Public Clients)

Best for browser-based applications that cannot securely store secrets.

```typescript
const client = {
  clientId: 'spa-client',
  redirectUris: ['https://myapp.com/callback'],
  scopes: ['read', 'openid', 'profile'],
  type: 'public'
};
```

**Security Features:**
- PKCE (Proof Key for Code Exchange) required
- No client secret
- Shorter token lifetimes

### Mobile Applications

Best for native mobile applications.

```typescript
const client = {
  clientId: 'mobile-app',
  redirectUris: ['myapp://auth/callback'],
  scopes: ['read', 'write', 'offline_access'],
  type: 'public'
};
```

**Security Features:**
- Custom URI schemes
- PKCE required
- Offline access with refresh tokens

## Scopes and Permissions

### Available Scopes

| Scope | Description |
|-------|-------------|
| `read` | Read access to resources |
| `write` | Write access to resources |
| `delete` | Delete access to resources |
| `admin` | Administrative access (includes all other scopes) |
| `openid` | OpenID Connect authentication |
| `profile` | Access to user profile information |
| `email` | Access to user email address |
| `offline_access` | Refresh token access |

### Scope Hierarchy

- `admin` includes all other scopes
- `write` includes `read` access
- `openid` is required for ID tokens

### Example Scope Requests

```bash
# Read-only access
scope=read+openid

# Full application access
scope=read+write+delete+openid+profile+email

# Administrative access (includes everything)
scope=admin+openid+profile+email
```

## Security Best Practices

### 1. PKCE (Proof Key for Code Exchange)

Always use PKCE for public clients and recommended for confidential clients:

```javascript
// Generate code verifier and challenge
const codeVerifier = generateCodeVerifier(); // 43-128 character random string
const codeChallenge = base64url(sha256(codeVerifier));

// Authorization request
const authUrl = `https://localhost:8181/oauth/authorize?` +
  `response_type=code&` +
  `client_id=YOUR_CLIENT_ID&` +
  `redirect_uri=YOUR_REDIRECT_URI&` +
  `scope=read+write+openid&` +
  `state=RANDOM_STATE&` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256`;

// Token request (include code_verifier)
// ... code_verifier=YOUR_CODE_VERIFIER
```

### 2. State Parameter

Always use the state parameter to prevent CSRF attacks:

```javascript
const state = generateRandomString(); // Store in session
// Include state in authorization request
// Verify state matches when handling callback
```

### 3. Validate Redirect URIs

- Use exact URL matching
- Prefer HTTPS in production
- Avoid wildcard redirect URIs

### 4. Token Storage

- **Web Apps**: Store tokens server-side in secure sessions
- **SPAs**: Use secure, httpOnly cookies or secure browser storage
- **Mobile**: Use platform-specific secure storage (Keychain, KeyStore)

## Client Management API

### List Clients (Admin Required)

```bash
curl -X GET http://localhost:8181/oauth/clients \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Create Client (Admin Required)

```bash
curl -X POST http://localhost:8181/oauth/clients \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "New Application",
    "redirect_uris": ["https://newapp.com/callback"],
    "client_type": "confidential",
    "scope": "read write"
  }'
```

### Update Client (Admin Required)

```bash
curl -X PUT http://localhost:8181/oauth/clients/CLIENT_ID \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated App Name",
    "scopes": ["read", "write", "admin"]
  }'
```

### Delete Client (Admin Required)

```bash
curl -X DELETE http://localhost:8181/oauth/clients/CLIENT_ID \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

## Error Handling

### Common Error Responses

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: client_id"
}
```

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired"
}
```

### Error Codes

- `invalid_request`: Missing or malformed parameters
- `invalid_client`: Client authentication failed
- `invalid_grant`: Authorization grant is invalid/expired
- `unauthorized_client`: Client not authorized for grant type
- `unsupported_grant_type`: Grant type not supported
- `invalid_scope`: Invalid or unauthorized scope
- `server_error`: Internal server error

## Testing and Development

### Development Client

Use the default development client for testing:

```bash
# Client ID: mcp-template-client
# Client Secret: mcp-template-secret-key
# Redirect URI: http://localhost:3000/auth/callback

# Test authorization URL
http://localhost:8181/oauth/authorize?response_type=code&client_id=mcp-template-client&redirect_uri=http://localhost:3000/auth/callback&scope=read+write+openid&state=test-state
```

### OAuth Flow Testing

1. Start the HTTP server: `node dist/http-server.js`
2. Navigate to the authorization URL in your browser
3. The server will simulate user consent and redirect with an authorization code
4. Exchange the code for tokens using curl or your application

### Debug Information

Enable debug logging:

```bash
LOG_LEVEL=debug node dist/http-server.js
```

## Production Deployment

### Environment Variables

```bash
# OAuth Configuration
OAUTH_CLIENT_ID=your-production-client-id
OAUTH_CLIENT_SECRET=your-secure-production-secret
OAUTH_REDIRECT_URI=https://yourapp.com/auth/callback
OAUTH_ISSUER=https://your-auth-server.com

# Server Configuration
PORT=8181
HOST=0.0.0.0
```

### Security Checklist

- [ ] Use HTTPS in production
- [ ] Generate strong, random client secrets (32+ characters)
- [ ] Validate all redirect URIs
- [ ] Implement proper CORS policies
- [ ] Use secure session configuration
- [ ] Enable rate limiting
- [ ] Implement proper logging and monitoring
- [ ] Use environment variables for secrets
- [ ] Implement token cleanup and expiration
- [ ] Test PKCE implementation
- [ ] Verify state parameter validation

### Monitoring

The OAuth provider includes built-in statistics:

```bash
curl -X GET http://localhost:8181/oauth/stats \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

Response:
```json
{
  "clients": 5,
  "activeCodes": 2,
  "activeAccessTokens": 15,
  "activeRefreshTokens": 12
}
```

## Troubleshooting

### Common Issues

1. **"Invalid redirect URI"**
   - Ensure the redirect URI exactly matches what's registered
   - Check for trailing slashes, query parameters, or case differences

2. **"Invalid client"**
   - Verify client ID and secret are correct
   - Check if client is registered in the system

3. **"Code expired"**
   - Authorization codes expire after 10 minutes
   - Don't reuse authorization codes

4. **"Invalid PKCE"**
   - Ensure code_verifier matches the code_challenge
   - Use correct challenge method (S256 recommended)

### Debug Steps

1. Check server logs for detailed error information
2. Verify client registration with `/oauth/clients` endpoint
3. Test with simple curl commands first
4. Validate URLs and parameters carefully
5. Check token expiration times

For additional support, review the source code in `src/auth/` or check the server logs for detailed error messages.