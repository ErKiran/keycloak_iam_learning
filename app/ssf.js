const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const router = express.Router();
const setBodyParser = express.text({ type: ["application/secevent+jwt", "text/plain"] });

const CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
const CAEP_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
const SSF_VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification";
const MAX_EVENTS = 100;
const JWKS_CACHE_MS = 5 * 60 * 1000;

const receivedEvents = [];
let jwksCache = {
  fetchedAt: 0,
  keys: [],
};

function resolveBaseUrl(req) {
  return process.env.APP_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function bearerToken() {
  return process.env.SSF_BEARER_TOKEN || process.env.SSF_RECEIVER_TOKEN || "";
}

function allowedAlgorithms() {
  return String(process.env.SSF_ALLOWED_ALGORITHMS || "RS256")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

async function getJwks() {
  const jwksUrl = process.env.SSF_JWKS_URL;
  if (!jwksUrl) {
    throw new Error("SSF_JWKS_URL is not configured");
  }

  const now = Date.now();
  if (jwksCache.keys.length > 0 && now - jwksCache.fetchedAt < JWKS_CACHE_MS) {
    return jwksCache.keys;
  }

  const response = await axios.get(jwksUrl, { timeout: 10000 });
  const keys = Array.isArray(response.data?.keys) ? response.data.keys : [];
  jwksCache = { fetchedAt: now, keys };
  return keys;
}

function jwkToPem(jwk) {
  return crypto.createPublicKey({ key: jwk, format: "jwk" }).export({
    type: "spki",
    format: "pem",
  });
}

async function verifySetToken(setToken, req) {
  const jwksUrl = process.env.SSF_JWKS_URL;
  if (!jwksUrl) {
    return jwt.decode(setToken, { complete: true })?.payload;
  }

  const decoded = jwt.decode(setToken, { complete: true });
  const kid = decoded?.header?.kid;
  const alg = decoded?.header?.alg;
  if (!kid) throw new Error("SET header is missing kid");
  if (!allowedAlgorithms().includes(alg)) throw new Error("SET uses an unsupported signing algorithm");

  const keys = await getJwks();
  const jwk = keys.find((key) => key.kid === kid);
  if (!jwk) throw new Error("No matching key found in SSF_JWKS_URL");

  const expectedAudience = process.env.SSF_EXPECTED_AUDIENCE || (decoded?.payload?.aud ? resolveBaseUrl(req) : undefined);

  return jwt.verify(setToken, jwkToPem(jwk), {
    algorithms: allowedAlgorithms(),
    issuer: process.env.SSF_EXPECTED_ISSUER || undefined,
    audience: expectedAudience,
  });
}

function requireSsfBearer(req, res, next) {
  const expectedToken = bearerToken();
  if (!expectedToken) return next();

  if (req.get("authorization") !== `Bearer ${expectedToken}`) {
    return res.status(401).json({ err: "invalid_request", description: "Missing or invalid SSF bearer token" });
  }

  return next();
}

function ssfConfiguration(req, res) {
  const baseUrl = resolveBaseUrl(req);

  res.json({
    issuer: baseUrl,
    spec_version: "1_0-04",
    delivery_methods_supported: ["urn:ietf:rfc:8935"],
    push_endpoint: `${baseUrl}/ssf/events`,
    events_supported: [CAEP_SESSION_REVOKED, CAEP_CREDENTIAL_CHANGE, SSF_VERIFICATION],
    authorization_schemes: [
      {
        spec_urn: "urn:ietf:rfc:6750",
        scheme: "bearer",
        description: "Send Authorization: Bearer <SSF_BEARER_TOKEN> when SSF_BEARER_TOKEN is configured.",
      },
    ],
  });
}

function extractSetToken(req) {
  if (typeof req.body === "string") return req.body.trim();
  if (typeof req.body?.set_token === "string") return req.body.set_token.trim();
  if (typeof req.body?.jwt === "string") return req.body.jwt.trim();
  return "";
}

function validateSetClaims(payload, req) {
  if (!payload || typeof payload !== "object") {
    return "SET payload could not be decoded";
  }

  if (!payload.iss) return "SET is missing iss";
  if (!payload.jti) return "SET is missing jti";
  if (!payload.iat) return "SET is missing iat";
  if (!payload.events || typeof payload.events !== "object" || Object.keys(payload.events).length === 0) {
    return "SET is missing events";
  }

  const expectedIssuer = process.env.SSF_EXPECTED_ISSUER;
  if (expectedIssuer && payload.iss !== expectedIssuer) {
    return "SET issuer is not trusted";
  }

  const expectedAudience = process.env.SSF_EXPECTED_AUDIENCE || resolveBaseUrl(req);
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.aud && !audiences.includes(expectedAudience)) {
    return "SET audience does not match this receiver";
  }

  return null;
}

function eventSummary(payload) {
  const eventTypes = Object.keys(payload.events || {});
  const primaryEvent = payload.events?.[eventTypes[0]] || {};
  const subject = primaryEvent.subject || payload.sub_id || null;

  return {
    id: payload.jti,
    issuer: payload.iss,
    audience: payload.aud,
    issuedAt: payload.iat,
    eventTypes,
    subject,
    receivedAt: new Date().toISOString(),
    payload,
  };
}

function setDeliveryError(res, code, description) {
  return res.status(400).json({ err: code, description });
}

router.get("/.well-known/ssf-configuration", ssfConfiguration);
router.get("/ssf/configuration", ssfConfiguration);

router.post("/ssf/events", requireSsfBearer, setBodyParser, async (req, res) => {
  const setToken = extractSetToken(req);
  if (!setToken) {
    return setDeliveryError(res, "invalid_request", "Missing Security Event Token");
  }

  let payload;
  try {
    payload = await verifySetToken(setToken, req);
    const validationError = validateSetClaims(payload, req);
    if (validationError) {
      return setDeliveryError(res, "invalid_request", validationError);
    }
  } catch (err) {
    return setDeliveryError(res, "invalid_request", err.message || "SET signature verification failed");
  }

  receivedEvents.unshift(eventSummary(payload));
  receivedEvents.splice(MAX_EVENTS);

  return res.status(202).send();
});

router.get("/ssf/events", requireSsfBearer, (req, res) => {
  res.json({
    total: receivedEvents.length,
    events: receivedEvents,
  });
});

module.exports = router;
