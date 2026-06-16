const https = require("node:https");
const { URL } = require("node:url");

const axios = require("axios");

const FETCH_TIMEOUT_MS = 8000;

const SENSITIVE_PATHS = [
  {
    path: "/.git/HEAD",
    severity: "high",
    label: "Git metadata",
    validate(body, contentType) {
      if (contentType.includes("text/html")) {
        return false;
      }
      const trimmed = body.trim();
      return (
        /^ref:\s+refs\/heads\//i.test(trimmed) ||
        /^[a-f0-9]{40}$/i.test(trimmed)
      );
    },
  },
  {
    path: "/.env",
    severity: "high",
    label: "Environment file",
    validate(body, contentType) {
      if (contentType.includes("text/html")) {
        return false;
      }
      return /(^|\n)\s*[A-Z0-9_]+\s*=\s*.+/m.test(body);
    },
  },
  {
    path: "/.DS_Store",
    severity: "medium",
    label: "Directory metadata",
    validate(body, contentType) {
      if (contentType.includes("text/html")) {
        return false;
      }
      return (
        body.includes("Bud1") ||
        contentType.includes("application/octet-stream")
      );
    },
  },
  {
    path: "/server-status",
    severity: "medium",
    label: "Server status page",
    validate(body) {
      const lower = body.toLowerCase();
      return (
        lower.includes("apache server status") ||
        lower.includes("server uptime")
      );
    },
  },
  {
    path: "/phpinfo.php",
    severity: "high",
    label: "PHP info page",
    validate(body) {
      const lower = body.toLowerCase();
      return lower.includes("php version") && lower.includes("phpinfo()");
    },
  },
];

const WEIGHTS = { low: 1, medium: 2, high: 3 };

function addFinding(findings, finding) {
  findings.push(finding);
}

function cookieFindings(setCookieHeaders) {
  const findings = [];

  if (!Array.isArray(setCookieHeaders)) {
    return findings;
  }

  for (const cookie of setCookieHeaders) {
    const lower = cookie.toLowerCase();

    if (!lower.includes("secure")) {
      addFinding(findings, {
        severity: "high",
        title: "Cookie missing Secure flag",
        detail: cookie,
      });
    }

    if (!lower.includes("httponly")) {
      addFinding(findings, {
        severity: "medium",
        title: "Cookie missing HttpOnly flag",
        detail: cookie,
      });
    }

    if (!lower.includes("samesite=")) {
      addFinding(findings, {
        severity: "low",
        title: "Cookie missing SameSite attribute",
        detail: cookie,
      });
    }
  }

  return findings;
}

function headerFindings(headers) {
  const findings = [];

  if (headers.server) {
    addFinding(findings, {
      severity: /\d/.test(headers.server) ? "medium" : "low",
      title: "Server header exposed",
      detail: `Server: ${headers.server}`,
    });
  }

  if (headers["x-powered-by"]) {
    addFinding(findings, {
      severity: "medium",
      title: "Technology disclosure via X-Powered-By",
      detail: `X-Powered-By: ${headers["x-powered-by"]}`,
    });
  }

  if (headers["x-aspnet-version"]) {
    addFinding(findings, {
      severity: "medium",
      title: "ASP.NET version disclosure",
      detail: `X-AspNet-Version: ${headers["x-aspnet-version"]}`,
    });
  }

  if (headers.via) {
    addFinding(findings, {
      severity: "low",
      title: "Proxy/CDN chain disclosure via Via header",
      detail: `Via: ${headers.via}`,
    });
  }

  if (headers["x-generator"]) {
    addFinding(findings, {
      severity: "low",
      title: "Generator header exposed",
      detail: `X-Generator: ${headers["x-generator"]}`,
    });
  }

  return findings;
}

function isLikelySpaFallback(body, contentType) {
  const lower = body.toLowerCase();
  return (
    contentType.includes("text/html") &&
    (lower.includes("<!doctype html") || lower.includes("<html"))
  );
}

async function tryPath(baseUrl, item, httpsAgent) {
  const { path, severity, label, validate } = item;
  const url = new URL(path, baseUrl).toString();

  const response = await axios.get(url, {
    timeout: FETCH_TIMEOUT_MS,
    maxRedirects: 5,
    httpsAgent,
    responseType: "text",
    validateStatus: () => true,
    maxContentLength: 200_000,
    headers: { "User-Agent": "SecurityScanner/1.0" },
  });

  const contentType = String(
    response.headers["content-type"] || "",
  ).toLowerCase();
  const body = typeof response.data === "string" ? response.data : "";

  if (
    response.status < 400 &&
    !isLikelySpaFallback(body, contentType) &&
    validate(body, contentType)
  ) {
    return {
      severity,
      title: `Potentially exposed sensitive endpoint: ${label}`,
      detail: `${url} responded with status ${response.status}`,
    };
  }

  return null;
}

function exposureScore(findings) {
  return findings.reduce(
    (score, finding) => score + (WEIGHTS[finding.severity] || 0),
    0,
  );
}

function exposureLevel(score) {
  if (score >= 8) return "high";
  if (score >= 4) return "medium";
  return "low";
}

async function scanExposure(url) {
  const httpsAgent = new https.Agent({ rejectUnauthorized: true });

  const findings = [];

  const baseResponse = await axios.get(url, {
    timeout: FETCH_TIMEOUT_MS,
    maxRedirects: 5,
    httpsAgent,
    responseType: "stream",
    validateStatus: () => true,
    headers: { "User-Agent": "SecurityScanner/1.0" },
  });

  baseResponse.data.destroy();

  const baseUrl = baseResponse.request?.res?.responseUrl || url;
  const headers = baseResponse.headers || {};

  findings.push(...headerFindings(headers));
  findings.push(...cookieFindings(headers["set-cookie"]));

  for (const item of SENSITIVE_PATHS) {
    try {
      const finding = await tryPath(baseUrl, item, httpsAgent);
      if (finding) {
        findings.push(finding);
      }
    } catch (_error) {
      // Ignore path-specific fetch failures and continue scanning.
    }
  }

  const score = exposureScore(findings);

  return {
    target: url,
    baseStatusCode: baseResponse.status,
    findings,
    summary: {
      score,
      level: exposureLevel(score),
      totalFindings: findings.length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
    },
  };
}

module.exports = { scanExposure };
