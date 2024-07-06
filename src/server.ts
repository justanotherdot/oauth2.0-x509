import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import type { JwtPayload } from 'jsonwebtoken';
import * as jose from 'node-jose';

// TODO: multiple routes here actually belong in separate servers.

const app = express();
const port = 3000;

// Load certificates
const privateKey = fs.readFileSync(path.join(__dirname, '../certs/private.key'), 'utf8');
const certificate = fs.readFileSync(path.join(__dirname, '../certs/certificate.pem'), 'utf8');
const kid =  crypto.createHash('sha256').update(certificate).digest('hex');

// In-memory store for simplicity (use a database in production)
const clients: { [key: string]: { secret: string, redirectUri: string } } = {
  'client123': { secret: 'secret123', redirectUri: 'http://localhost:3000/callback' }
};
const authorizationCodes: { [key: string]: string } = {};
const tokens: { [key: string]: string } = {};

app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, state } = req.query;

  if (response_type !== 'code' || !clients[client_id as string]) {
    return res.status(400).send('Invalid request');
  }

  const code = crypto.randomBytes(16).toString('hex');
  authorizationCodes[code] = client_id as string;

  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.append('code', code);
  if (state) {
    redirectUrl.searchParams.append('state', state as string);
  }

  res.redirect(redirectUrl.toString());
});

app.post('/token', express.json(), (req, res) => {
  const { grant_type, code, client_id, client_secret } = req.body;

  if (grant_type !== 'authorization_code' || !authorizationCodes[code] || 
      authorizationCodes[code] !== client_id || clients[client_id].secret !== client_secret) {
    return res.status(400).send('Invalid request');
  }

  delete authorizationCodes[code];

  const accessToken = jwt.sign({ client_id }, privateKey, { 
    algorithm: 'RS256',
    expiresIn: '1h',
    issuer: 'https://your-oauth-server.com',
    subject: client_id,
    keyid: kid,
  });

  tokens[accessToken] = client_id;

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600
  });
});

app.get('/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send('No token provided');
  }

  const token = authHeader.split(' ')[1];
  // WARNING: This is decoded, not verified; do not trust claims or payload
  // details other than `kid` until `verify` has been called.
  const tokenDecode = jwt.decode(token, { complete: true });
  if (tokenDecode === null) {
    return;
  }

  const jwks = await fetch('http://localhost:3000/.well-known/jwks.json').then((x) => x.json());
  const key = jwks.keys.find((k: any) => k.kid === tokenDecode.header.kid);
  const cert = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;
  
  try {
    const decoded = jwt.verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload;
    res.json({ user_id: decoded.sub, client_id: decoded.client_id });
  } catch (error) {
    res.status(401).send('Invalid token');
  }
});

app.get('/callback', (req, res) => {
  const { code, state } = req.query;
  if (code) {
    res.send(`Authorization code received: ${code}. State: ${state || 'Not provided'}`);
  } else {
    res.status(400).send('No authorization code received');
  }
});

app.get('/.well-known/jwks.json', async (_req, res) => {
  // Read your x509 public key from a file
  const publicKeyPem = certificate;
  const x509Cert = publicKeyPem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s/g, '');

  // Convert PEM to JWK and add the x5c parameter with your x509 certificate.
  const keystore = jose.JWK.createKeyStore();
  const key = await keystore.add(publicKeyPem, 'pem', {
    x5c: [x509Cert],
    kid,
  });
  const jwk = key.toJSON();
  
  // Create the JWK Set
  const jwks = {
    keys: [jwk]
  };

  res.json(jwks);
});

app.listen(port, () => {
  console.log(`OAuth2 server running at http://localhost:${port}`);
});
