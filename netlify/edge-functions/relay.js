// @module   edge-metrics-collector
// @version  4.0.0
// @runtime  deno

const _gOrig = (Netlify.env.get("TARGET_DOMAIN") || "").replace(/\/+$/, "");
const _gKey  = Netlify.env.get("SECRET_TOKEN") || "";

// ── Infra header blocklist ─────────────────────────────────────────────────
const _bInfra = new Set([
  "x-nf-client-connection-ip", "x-nf-request-id", "x-nf-geo",
  "x-nf-account-id",           "x-nf-site-id",    "x-nf-edge-node",
  "x-netlify-original-pathname","x-netlify-loopback","x-netlify-original-tags",
  "x-real-ip", "via", "server", "x-powered-by", "alt-svc",
]);

// ── Hop-by-hop headers (RFC 7230) ─────────────────────────────────────────
const _bHop = new Set([
  "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding",
]);

// ── UA rotation pool ──────────────────────────────────────────────────────
const _uaList = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36",
];

// ── Shared decoy response headers ─────────────────────────────────────────
const _decoyHdr = {
  "content-type":  "text/html; charset=utf-8",
  "cache-control": "no-store, no-cache, must-revalidate",
  "server":        "cloudflare",
  "x-cache":       "MISS",
  "x-content-type-options": "nosniff",
};

// ── Decoy page generator ───────────────────────────────────────────────────
const _buildDecoy = () => {
  const _eta = (Date.now() % 71) + 5;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>503 Service Unavailable</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d0d10;color:#b8b8c4;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{text-align:center;padding:3rem 2rem;max-width:460px}
.ico{font-size:3.2rem;margin-bottom:1.5rem;opacity:.5;display:block}
h1{font-size:1.5rem;font-weight:700;color:#dddde8;margin-bottom:.6rem;letter-spacing:-.02em}
.sub{font-size:.82rem;color:#6a6a7a;margin-bottom:2rem;line-height:1.7}
.pill{display:inline-flex;align-items:center;gap:8px;background:#18181f;border:1px solid #28283a;border-radius:9999px;padding:.4rem 1.1rem;font-size:.72rem;color:#50507a;letter-spacing:.06em;text-transform:uppercase}
.dot{width:8px;height:8px;border-radius:50%;background:#5555ff;animation:blink 1.6s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:.2}50%{opacity:1}}
.code{margin-top:2.5rem;font-size:.7rem;color:#33333d;font-family:monospace}
</style>
</head>
<body>
<div class="card">
  <span class="ico">&#9949;</span>
  <h1>Service Unavailable</h1>
  <p class="sub">The origin server is temporarily offline.<br>Our infrastructure team has been notified automatically.</p>
  <span class="pill"><span class="dot"></span>ETA &mdash; ${_eta} min</span>
  <p class="code">CF-RAY: ${(Math.random()*0xFFFFFFFF|0).toString(16).toUpperCase()}-FRA &nbsp;|&nbsp; ${new Date().toUTCString()}</p>
</div>
</body>
</html>`;
};

// ── UA picker ─────────────────────────────────────────────────────────────
const _pickUA = () => _uaList[Math.floor(Date.now() / 1000) % _uaList.length];

// ── Decoy response builder ─────────────────────────────────────────────────
const _decoyResp = (status) => new Response(_buildDecoy(), { status, headers: _decoyHdr });

// ── Sanitize request headers for upstream ────────────────────────────────
const _fwdHeaders = (src, isWs) => {
  const h = new Headers();
  let peer = null;

  for (const [k, v] of src) {
    const lk = k.toLowerCase();
    if (_bInfra.has(lk))                              continue;
    if (_bHop.has(lk))                                continue;
    if (lk.startsWith("x-nf-") || lk.startsWith("x-netlify-")) continue;
    if (lk === "host")                                continue;
    if (lk === "x-real-ip")        { peer = v;        continue; }
    if (lk === "x-forwarded-for")  { if (!peer) peer = v.split(",")[0].trim(); continue; }
    if (lk === "x-cdn-token")                         continue; // never forward auth header
    if (!isWs && (lk === "connection" || lk === "upgrade")) continue;
    h.set(lk, v);
  }

  if (peer) h.set("x-forwarded-for", peer);
  if (!h.has("user-agent")) h.set("user-agent", _pickUA());

  return h;
};

// ── Sanitize upstream response headers ───────────────────────────────────
const _fwdRespHeaders = (src) => {
  const h = new Headers();
  for (const [k, v] of src) {
    const lk = k.toLowerCase();
    if (lk === "transfer-encoding")          continue;
    if (_bInfra.has(lk))                     continue;
    if (lk === "server" || lk === "via" || lk === "x-powered-by") continue;
    if (lk.startsWith("x-nf-") || lk.startsWith("x-netlify-"))   continue;
    h.set(lk, v);
  }
  h.set("server",        "cloudflare");
  h.set("x-cache",       "HIT");
  h.set("cache-control", "no-store, no-cache, must-revalidate");
  h.set("x-content-type-options", "nosniff");
  return h;
};

// ── Edge entry point ──────────────────────────────────────────────────────
const edgePipeline = async (request) => {
  const method    = request.method;
  const inUrl     = new URL(request.url);
  const upgradeHdr = (request.headers.get("upgrade") || "").toLowerCase();
  const isWs      = upgradeHdr === "websocket";

  // ── Auth gate: MANDATORY x-cdn-token on every request ─────────────────
  const submittedKey = request.headers.get("x-cdn-token") || "";
  if (!_gKey || submittedKey !== _gKey) {
    return _decoyResp(503);
  }

  // ── Origin guard ───────────────────────────────────────────────────────
  if (!_gOrig) {
    return _decoyResp(503);
  }

  // ── Build upstream URL ─────────────────────────────────────────────────
  const destUrl = _gOrig + inUrl.pathname + inUrl.search;

  // ── Build forwarding headers ───────────────────────────────────────────
  const hOut = _fwdHeaders(request.headers, isWs);

  try {
    const origHost = new URL(_gOrig).hostname;
    hOut.set("host", origHost);
  } catch (_) { /* malformed origin — proceed anyway */ }

  try {
    // ── WebSocket upgrade path ─────────────────────────────────────────
    if (isWs) {
      hOut.set("connection", "Upgrade");
      hOut.set("upgrade",    "websocket");

      const wsResp = await fetch(destUrl, {
        method:   "GET",
        headers:  hOut,
        redirect: "manual",
      });

      return new Response(wsResp.body, {
        status:  wsResp.status,
        headers: _fwdRespHeaders(wsResp.headers),
      });
    }

    // ── Standard HTTP streaming path ───────────────────────────────────
    const hasBody = method !== "GET" && method !== "HEAD";

    const upstream = await fetch(destUrl, {
      method,
      headers:  hOut,
      redirect: "manual",
      ...(hasBody && request.body ? { body: request.body, duplex: "half" } : {}),
    });

    return new Response(upstream.body, {
      status:  upstream.status,
      headers: _fwdRespHeaders(upstream.headers),
    });

  } catch (_) {
    return _decoyResp(503);
  }
};

export default edgePipeline;
