const axios = require("axios");
const { parseStringPromise } = require("xml2js");
const { normalizeCertificateInput } = require("./x509_certificate");

function ensureArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function toPemCertificate(cert = "") {
  return normalizeCertificateInput(cert);
}

function pickSigningCertificates(keyDescriptors = []) {
  const certificates = [];

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
          if (pem) certificates.push(pem);
        }
      }
    }
  }

  return [...new Set(certificates)];
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
  const certs = pickSigningCertificates(idpDescriptor?.KeyDescriptor || idpDescriptor?.["md:KeyDescriptor"]);
  const certBundle = certs.join("\n\n");

  return {
    idpEntityId: entityID,
    ssoUrl,
    x509Certificate: certBundle,
    x509Certificates: certs,
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
