import { useMemo, useState } from "react";
import { launchConfetti } from "./helpers/useConfetti";
import "./App.css";

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [tlsResult, setTlsResult] = useState(null);
  const [headersResult, setHeadersResult] = useState(null);
  const [exposureResult, setExposureResult] = useState(null);
  const [corsResult, setCorsResult] = useState(null);

  const overallRiskLevel = useMemo(() => {
    if (!tlsResult && !headersResult && !exposureResult && !corsResult) {
      return null;
    }

    const tlsRiskCount = Object.values(tlsResult?.riskSignals || {}).filter(
      Boolean,
    ).length;
    const highHeaderIssues = (headersResult?.headers || []).filter(
      (header) =>
        header.severity === "high" && (!header.present || header.warning),
    ).length;
    const mediumHeaderIssues = (headersResult?.headers || []).filter(
      (header) =>
        header.severity === "medium" && (!header.present || header.warning),
    ).length;
    const exposureHigh = exposureResult?.summary?.high || 0;
    const exposureMedium = exposureResult?.summary?.medium || 0;
    const corsHigh = corsResult?.summary?.high || 0;
    const corsMedium = corsResult?.summary?.medium || 0;

    const weightedScore =
      tlsRiskCount * 2 +
      highHeaderIssues * 3 +
      mediumHeaderIssues +
      exposureHigh * 3 +
      exposureMedium * 2 +
      corsHigh * 3 +
      corsMedium * 2;

    if (weightedScore >= 6) return "high";
    if (weightedScore >= 2) return "medium";
    return "low";
  }, [tlsResult, headersResult, exposureResult, corsResult]);

  const tlsRiskLevel = useMemo(() => {
    if (!tlsResult?.riskSignals) {
      return null;
    }

    const risks = Object.values(tlsResult.riskSignals).filter(Boolean).length;
    if (risks === 0) return "low";
    if (risks === 1) return "medium";
    return "high";
  }, [tlsResult]);

  async function downloadReport() {
    const reportData = {
      tls: tlsResult,
      headers: headersResult,
      exposure: exposureResult,
      cors: corsResult,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: "application/json",
    });
    const reportUrl = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = reportUrl;
    a.download = "security_report.json";
    document.body.appendChild(a);
    a.click();

    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(reportUrl);
    }, 0);
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setTlsResult(null);
    setHeadersResult(null);
    setExposureResult(null);
    setCorsResult(null);

    try {
      const [tlsResponse, headersResponse, exposureResponse, corsResponse] =
        await Promise.all([
          fetch("/api/tls-info", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
          }),
          fetch("/api/headers", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
          }),
          fetch("/api/exposure", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
          }),
          fetch("/api/cors", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
          }),
        ]);

      const [tlsPayload, headersPayload, exposurePayload, corsPayload] =
        await Promise.all([
          tlsResponse.json(),
          headersResponse.json(),
          exposureResponse.json(),
          corsResponse.json(),
        ]);

      if (!tlsResponse.ok)
        throw new Error(tlsPayload.error || "TLS request failed");
      if (!headersResponse.ok)
        throw new Error(headersPayload.error || "Headers request failed");
      if (!exposureResponse.ok)
        throw new Error(exposurePayload.error || "Exposure request failed");
      if (!corsResponse.ok)
        throw new Error(corsPayload.error || "CORS request failed");

      const tlsSignals = Object.values(tlsPayload.riskSignals || {});
      const tlsIsLowRisk = tlsSignals.every((value) => !value);
      const exposureIsLowRisk = exposurePayload?.summary?.level === "low";
      const hasHighHeaderIssues = (headersPayload.headers || []).some(
        (header) =>
          header.severity === "high" && (!header.present || header.warning),
      );
      const corsHasHighFindings = (corsPayload.findings || []).some(
        (finding) => finding.severity === "high",
      );

      // Celebrate low risk with confetti (and maybe medium risk too because I want to see it more often :) )
      if (overallRiskLevel === "low" || overallRiskLevel === "medium") {
        launchConfetti({ x: window.innerWidth / 2, y: 180 });
      }

      setTlsResult(tlsPayload);
      setHeadersResult(headersPayload);
      setExposureResult(exposurePayload);
      setCorsResult(corsPayload);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unknown error",
      );
    } finally {
      setLoading(false);
    }
  }

  const sortedHeaders = useMemo(() => {
    if (!headersResult?.headers) return [];
    return [...headersResult.headers].sort((a, b) => {
      if (a.present !== b.present) return a.present ? 1 : -1;
      return (
        (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
      );
    });
  }, [headersResult]);

  return (
    <>
      <section className="scanner">
        <h1>Website Security Scanner</h1>
        <p className="subtitle">
          Inspect TLS certificate and HTTP security headers for any HTTPS
          website.
        </p>

        {overallRiskLevel ? (
          <p className={`risk risk-${overallRiskLevel}`}>
            Overall risk: {overallRiskLevel}
          </p>
        ) : null}

        <form className="scan-form" onSubmit={handleSubmit}>
          <input
            id="user-input"
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
            aria-label="Target URL"
          />
          <button type="submit" className="counter" disabled={loading}>
            {loading ? "Scanning..." : "Scan"}
          </button>
        </form>

        {error ? <p className="error">{error}</p> : null}

        {tlsResult ? (
          <section className="result" aria-live="polite">
            <h2>TLS / Certificate</h2>
            <p className={`risk risk-${tlsRiskLevel}`}>
              TLS risk level: {tlsRiskLevel}
            </p>
            <ul>
              <li>Protocol: {tlsResult.tls.protocol || "Unknown"}</li>
              <li>Cipher: {tlsResult.tls.cipher?.name || "Unknown"}</li>
              <li>
                Certificate trusted: {tlsResult.tls.authorized ? "Yes" : "No"}
              </li>
              <li>
                Expires in: {tlsResult.certificate.expiresInDays ?? "Unknown"}{" "}
                days
              </li>
              <li>Issuer: {tlsResult.certificate.issuer?.CN || "Unknown"}</li>
              <li>Subject: {tlsResult.certificate.subject?.CN || "Unknown"}</li>
              <li>
                Certificate chain length:{" "}
                {tlsResult.certificate.chainLength ?? "Unknown"}
              </li>

              {tlsResult.tls.authorizationError ? (
                <li className="header-warning">
                  ⚠ {tlsResult.tls.authorizationError}
                </li>
              ) : null}
            </ul>
          </section>
        ) : null}

        {corsResult ? (
          <section className="result" aria-live="polite">
            <h2>CORS Analysis</h2>
            <p>
              Findings: {corsResult.summary.totalFindings} (high:{" "}
              {corsResult.summary.high}, medium: {corsResult.summary.medium},
              low: {corsResult.summary.low})
            </p>
            {corsResult.findings.length === 0 ? (
              <p>No CORS misconfiguration findings from this probe.</p>
            ) : (
              <ul className="exposure-list">
                {corsResult.findings.map((finding, index) => (
                  <li key={`${finding.title}-${index}`}>
                    <span
                      className={`severity-pill severity-${finding.severity}`}
                    >
                      {finding.severity}
                    </span>
                    <strong>{finding.title}</strong>
                    <div className="finding-detail">{finding.detail}</div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        ) : null}

        {headersResult ? (
          <section className="result" aria-live="polite">
            <h2>Security Headers</h2>
            <table className="headers-table">
              <thead>
                <tr>
                  <th>Header</th>
                  <th>Status</th>
                  <th>Value / Note</th>
                </tr>
              </thead>
              <tbody>
                {sortedHeaders.map((h) => (
                  <tr
                    key={h.header}
                    className={
                      h.present
                        ? h.warning
                          ? "row-warn"
                          : "row-ok"
                        : `row-missing row-${h.severity}`
                    }
                  >
                    <td className="header-name">{h.header}</td>
                    <td className="header-status">
                      {h.present
                        ? h.warning
                          ? "⚠ Issue"
                          : "✓ Present"
                        : "✗ Missing"}
                    </td>
                    <td className="header-value">
                      {h.warning ?? h.value ?? (
                        <span className="missing-label">
                          {h.severity} severity
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        ) : null}

        {exposureResult ? (
          <section className="result" aria-live="polite">
            <h2>Exposure Check</h2>
            <p className={`risk risk-${exposureResult.summary.level}`}>
              Exposure level: {exposureResult.summary.level}
            </p>
            <p>
              Findings: {exposureResult.summary.totalFindings} (high:{" "}
              {exposureResult.summary.high}, medium:{" "}
              {exposureResult.summary.medium}, low: {exposureResult.summary.low}
              )
            </p>
            {exposureResult.findings.length === 0 ? (
              <p>No obvious exposure findings detected in this quick check.</p>
            ) : (
              <ul className="exposure-list">
                {exposureResult.findings.map((finding, index) => (
                  <li key={`${finding.title}-${index}`}>
                    <span
                      className={`severity-pill severity-${finding.severity}`}
                    >
                      {finding.severity}
                    </span>
                    <strong>{finding.title}</strong>
                    <div className="finding-detail">{finding.detail}</div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        ) : null}
        <section className="download-section">
          <button
            className="counter"
            onClick={downloadReport}
            disabled={
              !tlsResult && !headersResult && !exposureResult && !corsResult
            }
          >
            {" "}
            Download Report
          </button>
        </section>
      </section>
    </>
  );
}

export default App;
