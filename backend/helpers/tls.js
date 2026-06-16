const tls = require("node:tls");

const REQUEST_TIMEOUT_MS = 8000;

function daysUntil(dateString) {
  const expiryDate = new Date(dateString).getTime();
  const now = Date.now();
  return Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
}

function getHandshakeData(hostname, port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();

          if (!cert || Object.keys(cert).length === 0) {
            reject(new Error("No certificate was presented by the server."));
            socket.end();
            return;
          }

          resolve({
            authorized: socket.authorized,
            authorizationError: socket.authorizationError || null,
            protocol,
            cipher,
            certificate: cert,
          });

          socket.end();
        } catch (error) {
          reject(error);
          socket.end();
        }
      },
    );

    socket.setTimeout(REQUEST_TIMEOUT_MS, () => {
      reject(new Error("TLS handshake timed out."));
      socket.destroy();
    });

    socket.on("error", (error) => {
      reject(error);
      socket.destroy();
    });
  });
}

function buildCertificateChain(certificate) {
  const chain = [];
  const seenFingerprints = new Set();

  let current = certificate;
  while (current && current.fingerprint256) {
    if (seenFingerprints.has(current.fingerprint256)) {
      break;
    }

    seenFingerprints.add(current.fingerprint256);
    chain.push({
      subject: current.subject?.CN || null,
      issuer: current.issuer?.CN || null,
      validFrom: current.valid_from || null,
      validTo: current.valid_to || null,
      serialNumber: current.serialNumber || null,
      fingerprint256: current.fingerprint256 || null,
      signatureAlgorithm: current.signatureAlgorithm || null,
    });

    if (
      !current.issuerCertificate ||
      current.issuerCertificate.fingerprint256 === current.fingerprint256
    ) {
      break;
    }

    current = current.issuerCertificate;
  }

  return chain;
}

function analyzeCertificateSecurity(certificate) {
  const chain = buildCertificateChain(certificate);
  const leaf = chain[0] || null;

  return {
    chain,
    chainLength: chain.length,
    isSelfSignedLeaf:
      Boolean(leaf?.subject) &&
      Boolean(leaf?.issuer) &&
      leaf.subject === leaf.issuer,
    signatureAlgorithm: leaf?.signatureAlgorithm || null,
  };
}

module.exports = { daysUntil, getHandshakeData, analyzeCertificateSecurity };
