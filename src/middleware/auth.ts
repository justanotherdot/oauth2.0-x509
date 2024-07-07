import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

interface DecodedToken {
  sub: string;
  client_id: string;
  [key: string]: any;
}

// Declaration merge on request.
declare global {
  namespace Express {
    interface Request {
      user: DecodedToken;
    }
  }
}

export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send("Forbidden");
  }

  const token = authHeader.split(" ")[1];

  try {
    // Decode the token without verifying to get the kid
    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken) {
      throw new Error("Invalid token format");
    }

    // Fetch the JWKS
    const jwksResponse = await fetch(
      "http://localhost:3002/.well-known/jwks.json",
    );
    const jwks = await jwksResponse.json();

    // Find the correct key
    const key = jwks.keys.find((k: any) => k.kid === decodedToken.header.kid);
    if (!key) {
      throw new Error("No matching key found");
    }

    // Construct the certificate
    const cert = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;

    // Verify the token
    const verified = jwt.verify(token, cert, {
      algorithms: ["RS256"],
    }) as DecodedToken;

    // Attach the decoded token to the request object
    req.user = verified;

    next();
  } catch (error) {
    console.error("Token verification failed:", error);
    return res.status(401).json({
      message:
        "Sorry, your token is invalid or has expired. Please try logging in again.",
    });
  }
};
