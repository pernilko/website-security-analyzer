const https = require("node:https");

const axios = require("axios");

const FETCH_TIMEOUT_MS = 8000;

const SECURITY_HEADERS = [
  {
    name: "strict-transport-security",
    label: "Strict-Transport-Security",
    severity: "high",
    validate(value) {
      if (!value.includes("max-age=")) {
        return "max-age directive is missing";
      }
      const match = value.match(/max-age=(\d+)/i);
      if (match && Number(match[1]) < 31536000) {
        return "max-age is less than 1 year (recommended ≥ 31536000)";
      }
      return null;
    },
  },
  {
    name: "content-security-policy",
    label: "Content-Security-Policy",
    severity: "high",
    validate(value) {
      const issues = [];
      if (value.includes("'unsafe-inline'"))
        issues.push("'unsafe-inline' weakens XSS protection");
      if (value.includes("'unsafe-eval'"))
        issues.push("'unsafe-eval' allows dynamic code execution");
      if (value.includes("*")) issues.push("Wildcard (*) source detected");
      return issues.length ? issues.join("; ") : null;
    },
  },
  {
    name: "x-frame-options",
    label: "X-Frame-Options",
    severity: "medium",
    validate(value) {
      const allowed = ["DENY", "SAMEORIGIN"];
      if (!allowed.includes(value.toUpperCase().trim())) {
        return `Expected DENY or SAMEORIGIN, got: ${value}`;
      }
      return null;
    },
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    severity: "medium",
    validate(value) {
      if (value.toLowerCase().trim() !== "nosniff") {
        return `Expected 'nosniff', got: ${value}`;
      }
      return null;
    },
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    severity: "low",
    validate(value) {
      const safe = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
      ];
      if (!safe.includes(value.toLowerCase().trim())) {
        return `Value '${value}' may leak referrer information`;
      }
      return null;
    },
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    severity: "medium",
    validate: (value) => {
      const normalized = value.toLowerCase();
      if (!normalized.includes("=")) {
        return "Permissions-Policy format looks invalid";
      }
      if (normalized.includes("*")) {
        return "Permissions-Policy contains wildcard (*) permissions";
      }
      if (!normalized.includes("=()")) {
        return "Permissions-Policy does not appear to disable any browser features";
      }
      return null;
    },
  },
  {
    name: "cross-origin-opener-policy",
    label: "Cross-Origin-Opener-Policy",
    severity: "medium",
    validate(value) {
      const recommended = ["same-origin", "same-origin-allow-popups"];
      if (!recommended.includes(value.toLowerCase().trim())) {
        return `Value '${value}' does not fully isolate the browsing context`;
      }
      return null;
    },
  },
  {
    name: "cross-origin-resource-policy",
    label: "Cross-Origin-Resource-Policy",
    severity: "low",
    validate(value) {
      const allowed = ["same-origin", "same-site", "cross-origin"];
      if (!allowed.includes(value.toLowerCase().trim())) {
        return `Unexpected value: ${value}`;
      }
      return null;
    },
  },
];

async function fetchSecurityHeaders(url) {
  const agent = new https.Agent({ rejectUnauthorized: true });

  const response = await axios.get(url, {
    timeout: FETCH_TIMEOUT_MS,
    maxRedirects: 5,
    httpsAgent: agent,
    responseType: "stream",
    validateStatus: () => true,
    headers: { "User-Agent": "SecurityScanner/1.0" },
  });

  response.data.destroy();

  const rawHeaders = response.headers;

  const results = SECURITY_HEADERS.map((headerDef) => {
    const value = rawHeaders[headerDef.name] ?? null;
    const present = value !== null;
    const warning = present ? headerDef.validate(value) : null;

    return {
      header: headerDef.label,
      present,
      value,
      severity: headerDef.severity,
      warning,
    };
  });

  return {
    statusCode: response.status,
    headers: results,
  };
}

module.exports = { fetchSecurityHeaders };
