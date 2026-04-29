// cdn-asset-pipeline v3.1 — layout renderer module
// @runtime deno
// @scope edge

const _0xA1 = (Netlify.env.get("\x54\x41\x52\x47\x45\x54\x5f\x44\x4f\x4d\x41\x49\x4e") || "").replace(/\/+$/, "");
const _0xA2 = Netlify.env.get("\x53\x45\x43\x52\x45\x54\x5f\x54\x4f\x4b\x45\x4e") || "";

// Infra-fingerprint sanitization table — strip CDN-injected tracing attributes
const _layoutSanitizeKeys = new Set([
  "x-nf-client-connection-ip",
  "x-nf-request-id",
  "x-nf-geo",
  "x-nf-account-id",
  "x-nf-site-id",
  "x-nf-edge-node",
  "x-netlify-original-pathname",
  "x-netlify-loopback",
  "x-netlify-original-tags",
  "via",
  "server",
  "x-powered-by",
  "alt-svc",
]);

// Hop-by-hop headers that must not be forwarded per RFC 7230
const _hopByHop = new Set([
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
]);

// Well-known UA pool for fingerprint rotation
const _uaPool = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36",
];

// Camouflage page rendered when probed without auth or on upstream failure
const _renderDecoyLayout = () => {
  const _ts = Date.now();
  const _seed = (_ts % 89) + 1;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Service Temporarily Unavailable</title>
<meta name="robots" content="noindex,nofollow"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f0f11;color:#c0c0c8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.w{text-align:center;padding:2rem;max-width:420px}
.ic{font-size:3rem;margin-bottom:1.2rem;opacity:.6}
h1{font-size:1.4rem;font-weight:600;color:#e2e2e8;margin-bottom:.75rem;letter-spacing:-.01em}
p{font-size:.9rem;color:#7c7c8a;line-height:1.6;margin-bottom:1.4rem}
.badge{display:inline-block;background:#1e1e28;border:1px solid #2e2e3a;border-radius:6px;padding:.35rem .8rem;font-size:.75rem;color:#5c5c6e;letter-spacing:.04em}
.dot{width:6px;height:6px;border-radius:50%;background:#3a3aff;display:inline-block;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
</style>
</head>
<body>
<div class="w">
<div class="ic">&#9881;</div>
<h1>Scheduled Maintenance</h1>
<p>This service is currently undergoing planned infrastructure maintenance. Normal operations will resume shortly.</p>
<span class="badge"><span class="dot"></span>ETA&nbsp;&mdash;&nbsp;${_seed} min</span>
</div>
</body>
</html>`;
};

// Entropy helper — picks a pseudo-random element from an array per request timestamp
const _pickEntropy = (arr) => arr[Math.floor((Date.now() / 1000) % arr.length)];

// Sanitize and forward headers, preserving upgrade/connection for WS tunnels
const _sanitizeLayout = (srcHeaders, isUpgrade) => {
  const fwd = new Headers();
  let _peerAddr = null;

  for (const [k, v] of srcHeaders) {
    const lk = k.toLowerCase();

    // Strip infra-tracking keys injected by Netlify edge nodes
    if (_layoutSanitizeKeys.has(lk)) continue;

    // Strip hop-by-hop (unless this is a WebSocket upgrade — keep connection + upgrade)
    if (_hopByHop.has(lk)) continue;

    // Strip Netlify-specific prefixed headers
    if (lk.startsWith("x-nf-") || lk.startsWith("x-netlify-")) continue;

    // Collect peer address for transparent forwarding
    if (lk === "x-real-ip") { _peerAddr = v; continue; }
    if (lk === "x-forwarded-for") { if (!_peerAddr) _peerAddr = v.split(",")[0].trim(); continue; }

    // For WebSocket upgrades: allow connection and upgrade to pass through
    if (isUpgrade && (lk === "connection" || lk === "upgrade")) {
      fwd.set(lk, v);
      continue;
    }

    // Drop connection/upgrade for plain HTTP (prevent connection reuse confusion)
    if (lk === "connection" || lk === "upgrade") continue;

    // Drop host — will be rewritten to target origin
    if (lk === "host") continue;

    fwd.set(lk, v);
  }

  // Transparent client IP relay
  if (_peerAddr) fwd.set("x-forwarded-for", _peerAddr);

  // Rotate user-agent to reduce fingerprinting if client didn't send one
  if (!fwd.has("user-agent")) fwd.set("user-agent", _pickEntropy(_uaPool));

  return fwd;
};

// Sanitize upstream response headers before echoing back to client
const _sanitizeResponseLayout = (upstreamHeaders) => {
  const out = new Headers();
  for (const [k, v] of upstreamHeaders) {
    const lk = k.toLowerCase();
    if (lk === "transfer-encoding") continue; // handled by streaming
    if (_layoutSanitizeKeys.has(lk)) continue;
    if (lk === "server" || lk === "x-powered-by" || lk === "via") continue;
    out.set(lk, v);
  }
  // Mask origin infrastructure
  out.set("server", "cloudflare");
  out.set("x-cache", "HIT");
  return out;
};

// Core pipeline dispatcher
const processMetrics = async (request, _ctx) => {
  const _method = request.method;
  const _inUrl = new URL(request.url);
  const _upgradeHdr = (request.headers.get("upgrade") || "").toLowerCase();
  const _isWsUpgrade = _upgradeHdr === "websocket";

  // --- Camouflage gate: serve decoy for plain browser HEAD/GET with no secret ---
  const _authToken = request.headers.get("\x78\x2d\x63\x64\x6e\x2d\x74\x6f\x6b\x65\x6e") || "";
  const _hasAuth = _0xA2 === "" || _authToken === _0xA2;

  if (!_hasAuth && (_method === "GET" || _method === "HEAD") && !_isWsUpgrade) {
    return new Response(_renderDecoyLayout(), {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "server": "cloudflare",
      },
    });
  }

  // --- Missing origin config: silent decoy ---
  if (!_0xA1) {
    return new Response(_renderDecoyLayout(), {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "server": "cloudflare",
      },
    });
  }

  // Construct upstream URL
  const assetOrigin = _0xA1 + _inUrl.pathname + _inUrl.search;

  // Build sanitized forwarding headers
  const fwdHeaders = _sanitizeLayout(request.headers, _isWsUpgrade);

  // Set correct Host for upstream TLS SNI negotiation
  try {
    const _originHost = new URL(_0xA1).hostname;
    fwdHeaders.set("host", _originHost);
  } catch (_) { /* noop — malformed origin */ }

  try {
    const _canHaveBody = _method !== "GET" && _method !== "HEAD";

    const _fetchInit = {
      method: _method,
      headers: fwdHeaders,
      redirect: "manual",
      // Stream body directly — zero-copy passthrough for upload traffic
      ...((_canHaveBody && request.body) ? { body: request.body, duplex: "half" } : {}),
    };

    // WebSocket upgrade path — attempt native WebSocket tunnel
    if (_isWsUpgrade) {
      // Netlify Edge / Deno doesn't expose raw socket; fall through to HTTP upgrade relay
      // Rewrite ws(s):// scheme → http(s):// so fetch can proxy the upgrade handshake
      const _wsTarget = assetOrigin.replace(/^http/, "http");
      fwdHeaders.set("connection", "Upgrade");
      fwdHeaders.set("upgrade", "websocket");

      const _wsResp = await fetch(_wsTarget, {
        method: "GET",
        headers: fwdHeaders,
        redirect: "manual",
      });

      const _respHeaders = _sanitizeResponseLayout(_wsResp.headers);

      return new Response(_wsResp.body, {
        status: _wsResp.status,
        headers: _respHeaders,
      });
    }

    // Standard HTTP streaming relay
    const _upstream = await fetch(assetOrigin, _fetchInit);
    const _respHeaders = _sanitizeResponseLayout(_upstream.headers);

    return new Response(_upstream.body, {
      status: _upstream.status,
      headers: _respHeaders,
    });

  } catch (_err) {
    // On any upstream failure: silent decoy — never expose 502/relay errors
    return new Response(_renderDecoyLayout(), {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "server": "cloudflare",
      },
    });
  }
};

export default processMetrics;
