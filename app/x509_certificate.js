const { X509Certificate, createHash } = require("crypto");

function wrapPem(base64) {
  const lines = String(base64 || "").match(/.{1,64}/g) || [];
  return [
    "-----BEGIN CERTIFICATE-----",
    ...lines,
    "-----END CERTIFICATE-----",
  ].join("\n");
}

function certToPem(cert) {
  return wrapPem(cert.raw.toString("base64"));
}

function parseCertificate(value) {
  try {
    return new X509Certificate(value);
  } catch (err) {
    return null;
  }
}

function decodeTextCandidates(buffer) {
  const candidates = [];
  const input = Buffer.isBuffer(buffer) ? buffer : Buffer.from(String(buffer || ""), "utf8");

  candidates.push(input.toString("utf8"));

  if (input.length >= 2) {
    const hasUtf16LeBom = input[0] === 0xff && input[1] === 0xfe;
    const hasUtf16BeBom = input[0] === 0xfe && input[1] === 0xff;
    const sample = input.subarray(0, Math.min(input.length, 200));
    const oddNulls = sample.filter((byte, index) => index % 2 === 1 && byte === 0).length;
    const evenNulls = sample.filter((byte, index) => index % 2 === 0 && byte === 0).length;

    if (hasUtf16LeBom || oddNulls > sample.length / 8) {
      candidates.push(input.toString("utf16le"));
    }

    if (hasUtf16BeBom || evenNulls > sample.length / 8) {
      const swapped = Buffer.alloc(input.length);
      for (let index = 0; index < input.length - 1; index += 2) {
        swapped[index] = input[index + 1];
        swapped[index + 1] = input[index];
      }
      candidates.push(swapped.toString("utf16le"));
    }
  }

  return [...new Set(candidates.map((entry) => entry.replace(/^\uFEFF/, "").trim()).filter(Boolean))];
}

function extractPemBlocks(text) {
  const blocks = String(text || "").match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return (blocks || []).map((entry) => entry.trim()).filter(Boolean);
}

function stripPemNoise(text) {
  return String(text || "")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "")
    .trim();
}

function parseBase64Certificate(text) {
  const normalized = stripPemNoise(text);
  if (!normalized || !/^[A-Za-z0-9+/=]+$/.test(normalized)) return null;

  const der = Buffer.from(normalized, "base64");
  return parseCertificate(der);
}

function normalizeCertificateInput(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(String(input || ""), "utf8");
  if (!buffer.length) return "";

  const certificates = [];
  for (const text of decodeTextCandidates(buffer)) {
    const pemBlocks = extractPemBlocks(text);

    for (const block of pemBlocks) {
      const cert = parseCertificate(block);
      if (cert) certificates.push(cert);
    }

    if (certificates.length > 0) continue;

    const base64Cert = parseBase64Certificate(text);
    if (base64Cert) certificates.push(base64Cert);
  }

  if (certificates.length === 0) {
    const derCert = parseCertificate(buffer);
    if (derCert) certificates.push(derCert);
  }

  const byFingerprint = new Map();
  for (const cert of certificates) {
    byFingerprint.set(cert.fingerprint256, cert);
  }

  return [...byFingerprint.values()].map(certToPem).join("\n\n");
}

function normalizeCertificateBundle(input) {
  return normalizeCertificateInput(input);
}

function certificateSummary(cert = "") {
  const pem = normalizeCertificateBundle(cert);
  const certs = extractPemBlocks(pem);
  const fingerprints = certs
    .map((entry) => stripPemNoise(entry))
    .filter(Boolean)
    .map((body) => createHash("sha256").update(body).digest("hex"));

  return {
    pem,
    certs,
    fingerprints,
  };
}

module.exports = {
  normalizeCertificateInput,
  normalizeCertificateBundle,
  certificateSummary,
};
