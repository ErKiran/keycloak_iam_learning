const axios = require("axios");
const { parseStringPromise } = require("xml2js");

function ensureArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function cleanCertificate(cert = "") {
  return String(cert || "")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "")
    .trim();
}

function toPemCertificate(cert = "") {
  const normalized = cleanCertificate(cert);
  if (!normalized) return "";
  const lines = normalized.match(/.{1,64}/g) || [];
  return [
    "-----BEGIN CERTIFICATE-----",
    ...lines,
    "-----END CERTIFICATE-----",
  ].join("\n");
}

function pickSigningCertificate(keyDescriptors = []) {
  for (const descriptor of keyDescriptors) {
    const use = descriptor?.$?.use;
    if (use && use !== "signing") continue;

    const keyInfos = ensureArray(descriptor?.KeyInfo);
    for (const keyInfo of keyInfos) {
      const x509Datas = ensureArray(keyInfo?.X509Data);
      for (const x509Data of x509Datas) {
        const certs = ensureArray(x509Data?.X509Certificate);
        for (const cert of certs) {
          const pem = toPemCertificate(cert);
          if (pem) return pem;
        }
      }
    }
  }

  return "";
}

function pickSsoUrl(singleSignOnServices = []) {
  const services = ensureArray(singleSignOnServices);
  const redirectBinding = services.find(
    (svc) => svc?.$?.Binding === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  );
  if (redirectBinding?.$?.Location) return redirectBinding.$.Location;

  const postBinding = services.find(
    (svc) => svc?.$?.Binding === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  );
  if (postBinding?.$?.Location) return postBinding.$.Location;

  return services[0]?.$?.Location || "";
}

async function parseIdpMetadataXml(xml) {
  const parsed = await parseStringPromise(xml, {
    explicitArray: false,
    trim: true,
  });

  const entityDescriptor = parsed?.EntityDescriptor || parsed?.["md:EntityDescriptor"];
  if (!entityDescriptor) {
    throw new Error("Invalid metadata XML: missing EntityDescriptor");
  }

  const entityID = entityDescriptor?.$?.entityID || "";
  const idpDescriptor = entityDescriptor?.IDPSSODescriptor || entityDescriptor?.["md:IDPSSODescriptor"];
  if (!idpDescriptor) {
    throw new Error("Invalid metadata XML: missing IDPSSODescriptor");
  }

  const ssoUrl = pickSsoUrl(idpDescriptor?.SingleSignOnService || idpDescriptor?.["md:SingleSignOnService"]);
  const cert = pickSigningCertificate(idpDescriptor?.KeyDescriptor || idpDescriptor?.["md:KeyDescriptor"]);

  return {
    idpEntityId: entityID,
    ssoUrl,
    x509Certificate: cert,
  };
}

async function fetchAndParseIdpMetadata(metadataUrl) {
  const response = await axios.get(metadataUrl, {
    timeout: 15000,
    responseType: "text",
  });

  const xml = String(response.data || "").trim();
  if (!xml) {
    throw new Error("Metadata URL returned empty response");
  }

  const parsed = await parseIdpMetadataXml(xml);
  return {
    xml,
    ...parsed,
  };
}

module.exports = {
  parseIdpMetadataXml,
  fetchAndParseIdpMetadata,
};
