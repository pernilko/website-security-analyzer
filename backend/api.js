const net = require("node:net");

const { Router } = require("express");

const { analyzeCors } = require("./helpers/cors");
const { scanExposure } = require("./helpers/exposure");
const { fetchSecurityHeaders } = require("./helpers/headers");
const { resolvePublicAddresses } = require("./helpers/network");
const {
  analyzeCertificateSecurity,
  daysUntil,
  getHandshakeData,
} = require("./helpers/tls");
const { normalizeInputUrl } = require("./helpers/url");

const BLOCKED_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

const router = Router();

router.post("/tls-info", async (req, res) => {
  try {
    const parsedUrl = normalizeInputUrl(req.body?.url);
    const hostname = parsedUrl.hostname.toLowerCase();

    console.log(`Received scan request for: ${hostname}`);

    if (BLOCKED_HOSTS.has(hostname)) {
      res.status(400).json({ error: "Refused to scan localhost addresses." });
      return;
    }

    if (net.isIP(hostname)) {
      res.status(400).json({
        error: "Please provide a domain name instead of a direct IP address.",
      });
      return;
    }

    console.log(`Resolving DNS for: ${hostname}`);

    const dnsRecords = await resolvePublicAddresses(hostname);
    const handshake = await getHandshakeData(hostname, 443);
    const cert = handshake.certificate;
    const certSecurity = analyzeCertificateSecurity(cert);
    const expiresInDays = cert.valid_to ? daysUntil(cert.valid_to) : null;

    res.json({
      target: parsedUrl.toString(),
      host: hostname,
      dns: dnsRecords,
      tls: {
        protocol: handshake.protocol,
        cipher: handshake.cipher,
        authorized: handshake.authorized,
        authorizationError: handshake.authorizationError,
      },
      certificate: {
        subject: cert.subject,
        issuer: cert.issuer,
        subjectAltName: cert.subjectaltname || null,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        expiresInDays,
        serialNumber: cert.serialNumber || null,
        fingerprint256: cert.fingerprint256 || null,
        chain: certSecurity.chain,
        chainLength: certSecurity.chainLength,
        signatureAlgorithm: certSecurity.signatureAlgorithm,
      },
      riskSignals: {
        certificateUntrusted: !handshake.authorized,
        weakProtocol:
          handshake.protocol === "TLSv1" || handshake.protocol === "TLSv1.1",
        expiresSoon:
          typeof expiresInDays === "number" ? expiresInDays <= 30 : null,
        selfSignedLeaf: certSecurity.isSelfSignedLeaf,
      },
    });
  } catch (error) {
    res.status(400).json({
      error:
        error instanceof Error
          ? error.message
          : "Failed to inspect TLS details.",
    });
  }
});

router.get("/health", (_req, res) => {
  res.json({ ok: true });
});

router.post("/exposure", async (req, res) => {
  try {
    const parsedUrl = normalizeInputUrl(req.body?.url);
    const hostname = parsedUrl.hostname.toLowerCase();

    if (BLOCKED_HOSTS.has(hostname)) {
      res.status(400).json({ error: "Refused to scan localhost addresses." });
      return;
    }

    if (net.isIP(hostname)) {
      res.status(400).json({
        error: "Please provide a domain name instead of a direct IP address.",
      });
      return;
    }

    await resolvePublicAddresses(hostname);

    const result = await scanExposure(parsedUrl.toString());

    res.json({
      host: hostname,
      ...result,
    });
  } catch (error) {
    res.status(400).json({
      error:
        error instanceof Error
          ? error.message
          : "Failed to run exposure checks.",
    });
  }
});

router.post("/headers", async (req, res) => {
  try {
    const parsedUrl = normalizeInputUrl(req.body?.url);
    const hostname = parsedUrl.hostname.toLowerCase();

    if (BLOCKED_HOSTS.has(hostname)) {
      res.status(400).json({ error: "Refused to scan localhost addresses." });
      return;
    }

    if (net.isIP(hostname)) {
      res.status(400).json({
        error: "Please provide a domain name instead of a direct IP address.",
      });
      return;
    }

    await resolvePublicAddresses(hostname);

    const result = await fetchSecurityHeaders(parsedUrl.toString());

    res.json({
      target: parsedUrl.toString(),
      host: hostname,
      statusCode: result.statusCode,
      headers: result.headers,
    });
  } catch (error) {
    res.status(400).json({
      error:
        error instanceof Error
          ? error.message
          : "Failed to fetch security headers.",
    });
  }
});

router.post("/cors", async (req, res) => {
  try {
    const parsedUrl = normalizeInputUrl(req.body?.url);
    const hostname = parsedUrl.hostname.toLowerCase();

    if (BLOCKED_HOSTS.has(hostname)) {
      res.status(400).json({ error: "Refused to scan localhost addresses." });
      return;
    }

    if (net.isIP(hostname)) {
      res.status(400).json({
        error: "Please provide a domain name instead of a direct IP address.",
      });
      return;
    }

    await resolvePublicAddresses(hostname);

    const result = await analyzeCors(parsedUrl.toString());
    res.json({
      target: parsedUrl.toString(),
      host: hostname,
      ...result,
    });
  } catch (error) {
    res.status(400).json({
      error:
        error instanceof Error ? error.message : "Failed to run CORS analysis.",
    });
  }
});

module.exports = router;
