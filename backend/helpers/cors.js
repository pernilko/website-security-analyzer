const https = require("node:https");

const axios = require("axios");

const FETCH_TIMEOUT_MS = 8000;
const TEST_ORIGIN = "https://evil.example";

function summarize(findings) {
  return {
    totalFindings: findings.length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => finding.severity === "low").length,
  };
}

function getHeaderValue(headers, name) {
  return String(headers?.[name] || "").trim();
}

function analyzeHeaders(kind, headers) {
  const findings = [];
  const acao = getHeaderValue(headers, "access-control-allow-origin");
  const acac = getHeaderValue(headers, "access-control-allow-credentials");
  const acam = getHeaderValue(headers, "access-control-allow-methods");
  const acah = getHeaderValue(headers, "access-control-allow-headers");

  if (!acao) {
    return findings;
  }

  if (acao === "*") {
    findings.push({
      severity: acac.toLowerCase() === "true" ? "high" : "medium",
      title: `${kind}: Wildcard Access-Control-Allow-Origin`,
      detail: "Any origin can read responses when browser allows this policy.",
    });
  }

  if (acao === TEST_ORIGIN) {
    findings.push({
      severity: "high",
      title: `${kind}: Origin reflection detected`,
      detail: "Server reflected attacker-controlled Origin header value.",
    });
  }

  if (acac.toLowerCase() === "true" && (acao === "*" || acao === TEST_ORIGIN)) {
    findings.push({
      severity: "high",
      title: `${kind}: Credentials allowed with permissive origin`,
      detail:
        "Credentialed cross-origin requests may expose authenticated data.",
    });
  }

  if (
    acam.includes("*") ||
    acam.toUpperCase().includes("PUT") ||
    acam.toUpperCase().includes("DELETE")
  ) {
    findings.push({
      severity: "medium",
      title: `${kind}: Broad allowed methods`,
      detail: `Access-Control-Allow-Methods: ${acam || "(missing)"}`,
    });
  }

  if (acah.includes("*") || acah.toLowerCase().includes("authorization")) {
    findings.push({
      severity: "medium",
      title: `${kind}: Broad allowed headers`,
      detail: `Access-Control-Allow-Headers: ${acah || "(missing)"}`,
    });
  }

  return findings;
}

async function analyzeCors(url) {
  const httpsAgent = new https.Agent({ rejectUnauthorized: true });

  const commonConfig = {
    timeout: FETCH_TIMEOUT_MS,
    maxRedirects: 5,
    httpsAgent,
    validateStatus: () => true,
    responseType: "stream",
    headers: {
      "User-Agent": "SecurityScanner/1.0",
      Origin: TEST_ORIGIN,
    },
  };

  const [getResponse, optionsResponse] = await Promise.all([
    axios.get(url, commonConfig),
    axios.options(url, {
      ...commonConfig,
      headers: {
        ...commonConfig.headers,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization,content-type",
      },
    }),
  ]);

  getResponse.data.destroy();
  optionsResponse.data.destroy();

  const findings = [
    ...analyzeHeaders("GET", getResponse.headers),
    ...analyzeHeaders("OPTIONS", optionsResponse.headers),
  ];

  return {
    target: url,
    findings,
    summary: summarize(findings),
    observed: {
      get: {
        statusCode: getResponse.status,
        acao:
          getHeaderValue(getResponse.headers, "access-control-allow-origin") ||
          null,
        acac:
          getHeaderValue(
            getResponse.headers,
            "access-control-allow-credentials",
          ) || null,
      },
      options: {
        statusCode: optionsResponse.status,
        acao:
          getHeaderValue(
            optionsResponse.headers,
            "access-control-allow-origin",
          ) || null,
        acac:
          getHeaderValue(
            optionsResponse.headers,
            "access-control-allow-credentials",
          ) || null,
        acam:
          getHeaderValue(
            optionsResponse.headers,
            "access-control-allow-methods",
          ) || null,
        acah:
          getHeaderValue(
            optionsResponse.headers,
            "access-control-allow-headers",
          ) || null,
      },
    },
  };
}

module.exports = { analyzeCors };
