const dns = require("node:dns").promises;

function ipToInteger(ipv4) {
  return (
    ipv4
      .split(".")
      .map((part) => Number(part))
      .reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0
  );
}

function isPrivateIpv4(ip) {
  const value = ipToInteger(ip);
  const ranges = [
    ["10.0.0.0", "10.255.255.255"],
    ["172.16.0.0", "172.31.255.255"],
    ["192.168.0.0", "192.168.255.255"],
    ["127.0.0.0", "127.255.255.255"],
    ["169.254.0.0", "169.254.255.255"],
    ["100.64.0.0", "100.127.255.255"],
    ["0.0.0.0", "0.255.255.255"],
  ];

  return ranges.some(([start, end]) => {
    const startValue = ipToInteger(start);
    const endValue = ipToInteger(end);
    return value >= startValue && value <= endValue;
  });
}

function isPrivateIpv6(ip) {
  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80")
  );
}

function isBlockedAddress(address, family) {
  if (family === 4) {
    return isPrivateIpv4(address);
  }

  if (family === 6) {
    return isPrivateIpv6(address);
  }

  return false;
}

async function resolvePublicAddresses(hostname) {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });

  if (!records.length) {
    throw new Error("Hostname could not be resolved.");
  }

  const blockedRecord = records.find((record) =>
    isBlockedAddress(record.address, record.family),
  );

  if (blockedRecord) {
    throw new Error("Refused to scan internal or private network addresses.");
  }

  return records;
}

module.exports = { resolvePublicAddresses };
