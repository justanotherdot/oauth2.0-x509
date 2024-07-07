import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";
import * as jose from "node-jose";
import { authMiddleware } from "./middleware/auth";

// There are two to three parties involved in oauth 2.0.
//
// * The authorization server
// * The client
// * The resource server
//
// The authorization server is the third party who verifies
// identity and passes back an authorization token (JWT).
//
// The client is the application.
//
// The resource server is optional, and hosts things
// such as the JWKs for JWT verification. Usually,
// however, this is also the authorization server.

// TODO: refresh tokens.
// TODO: CSRF protection checks with state and session ids across login.

const app = express();
const port = process.env.PORT ?? 3000;

// Load certificates
const privateKey = fs.readFileSync(
  path.join(__dirname, "../certs/private.key"),
  "utf8",
);
const certificate = fs.readFileSync(
  path.join(__dirname, "../certs/certificate.pem"),
  "utf8",
);
const certificateStripped = certificate
  .replace(/-----BEGIN CERTIFICATE-----/, "")
  .replace(/-----END CERTIFICATE-----/, "")
  .replace(/\s/g, "");
const kid = crypto.createHash("sha256").update(certificate).digest("hex");

// In-memory store for simplicity (use a database in production)
const clients: { [key: string]: { secret: string; redirectUri: string } } = {
  client123: {
    secret: "secret123",
    redirectUri: "http://localhost:3000/oauth/exchange",
  },
};
const authorizationCodes: { [key: string]: string } = {};
const tokens: { [key: string]: string } = {};

// Authorize between the client (the application)
// and the third-party. If the client id and secret match
app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri, response_type, state } = req.query;

  if (response_type !== "code" || !clients[client_id as string]) {
    return res.status(400).send("Invalid request");
  }

  const code = crypto.randomBytes(16).toString("hex");
  authorizationCodes[code] = client_id as string;

  const redirectUrl = new URL(redirect_uri as string);
  redirectUrl.searchParams.append("code", code);
  if (state) {
    redirectUrl.searchParams.append("state", state as string);
  }

  res.redirect(redirectUrl.toString());
});

app.post("/token", express.json(), (req, res) => {
  const { grant_type, code, client_id, client_secret } = req.body;

  if (
    grant_type !== "authorization_code" ||
    !authorizationCodes[code] ||
    authorizationCodes[code] !== client_id ||
    clients[client_id].secret !== client_secret
  ) {
    return res.status(400).send("Invalid request");
  }

  delete authorizationCodes[code];

  const accessToken = jwt.sign({ client_id }, privateKey, {
    algorithm: "RS256",
    expiresIn: "1h",
    issuer: "http://localhost:3000",
    subject: client_id,
    keyid: kid,
  });

  tokens[accessToken] = client_id;

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
  });
});

app.get("/.well-known/jwks.json", async (_req, res) => {
  // Convert PEM to JWK and add the x5c parameter with your x509 certificate.
  const keystore = jose.JWK.createKeyStore();
  const key = await keystore.add(certificate, "pem", {
    x5c: [certificateStripped],
    kid,
  });
  const jwk = key.toJSON();

  // Create the JWK Set
  const jwks = {
    keys: [jwk],
  };

  res.json(jwks);
});

app.get("/userinfo", authMiddleware, async (req, res) => {
  res.json({ user_id: req.user.sub, client_id: req.user.client_id });
});

app.get("/oauth/exchange", async (req, res) => {
  const { code } = req.query;
  if (code) {
    const accessToken = await fetch("http://localhost:3002/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: "client123",
        client_secret: "secret123",
        redirect_uri: "http://localhost:3000/oauth/exchange",
      }),
    })
      .then((response) => response.json())
      .then((body) => body.access_token);
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3600000, // 1 hour
    });
    res.send("Login successful");
  } else {
    res.status(400).send("No authorization code received");
  }
});

app.get("/login", (_req, res) => {
  const authUrl = new URL("http://localhost:3002/authorize");
  authUrl.searchParams.append("client_id", "client123");
  authUrl.searchParams.append(
    "redirect_uri",
    "http://localhost:3000/oauth/exchange",
  );
  authUrl.searchParams.append("response_type", "code");

  const state = Math.random().toString(36).substring(7);
  authUrl.searchParams.append("state", state);

  res.cookie("oauth_state", state, { httpOnly: true, secure: true });

  res.redirect(authUrl.toString());
});

app.listen(port, () => {
  console.log(`OAuth2 server running at http://localhost:${port}`);
});
