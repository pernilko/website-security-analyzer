const { URL } = require("node:url");

function normalizeInputUrl(rawValue) {
  if (typeof rawValue !== "string") {
    throw new Error("URL must be a string.");
  }

  const trimmed = rawValue.trim();
  if (!trimmed) {
    throw new Error("URL is required.");
  }

  const normalized = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  const parsed = new URL(normalized);

  if (parsed.protocol !== "https:") {
    throw new Error("Only HTTPS URLs are supported for TLS inspection.");
  }

  if (!parsed.hostname) {
    throw new Error("URL must include a valid hostname.");
  }

  return parsed;
}

module.exports = { normalizeInputUrl };
