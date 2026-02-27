const DEFAULT_GRACE_MS = 2 * 60 * 60 * 1000;
const UNSCHEDULED_GRACE_MS = 10 * 60 * 1000;
const BOOTSTRAP_GRACE_MS = 20 * 1000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (url.pathname.startsWith("/access/")) {
      const token = url.pathname.split("/")[2];
      return handleAccessPage(request, env, token);
    }

    if (url.pathname.startsWith("/proxy/")) {
      const parts = url.pathname.split("/").slice(2);
      const token = parts.shift();
      const rest = parts.join("/");
      return handleProxy(request, env, token, rest, url.search);
    }

    if (url.pathname.startsWith("/exp/")) {
      return handleHostedAsset(request, env, url);
    }

    if (url.pathname === "/data/collect" && request.method === "POST") {
      return handleDataCollect(request, env);
    }

    if (url.pathname === "/token/verify" && request.method === "POST") {
      return handleTokenVerify(request, env);
    }

    if (url.pathname === "/token/status" && request.method === "GET") {
      const token = url.searchParams.get("token");
      return handleTokenStatus(request, env, token);
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders() });
  },
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      ...corsHeaders(),
    },
  });
}

async function getTokenData(env, token) {
  if (!env.ACCESS_KV) return null;
  const raw = await env.ACCESS_KV.get(`access:${token}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function saveTokenData(env, token, data) {
  if (!env.ACCESS_KV) return;
  const expiresAt = Number(data.expires_at_ms || data.grace_expires_at_ms || (Date.now() + DEFAULT_GRACE_MS));
  const ttlSeconds = Math.max(60, Math.floor((expiresAt - Date.now()) / 1000));
  await env.ACCESS_KV.put(`access:${token}`, JSON.stringify(data), { expirationTtl: ttlSeconds });
}

function parseCookies(header) {
  if (!header) return {};
  return header.split(";").reduce((acc, part) => {
    const [key, ...rest] = part.trim().split("=");
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join("="));
    return acc;
  }, {});
}

function getSessionId(request) {
  const cookies = parseCookies(request.headers.get("cookie"));
  return cookies.access_session || "";
}

function createSessionId() {
  if (crypto?.randomUUID) return crypto.randomUUID();
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function getClientInfo(request) {
  return {
    ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "",
    ua: request.headers.get("user-agent") || "",
  };
}

function isSameClient(data, sessionId, request, allowBootstrap = false) {
  if (data.used_session_id && sessionId) return data.used_session_id === sessionId;
  if (!data.used_session_id) return false;
  const info = getClientInfo(request);
  if (data.used_ip && info.ip && data.used_ip !== info.ip) return false;
  if (data.used_ua && info.ua && data.used_ua !== info.ua) return false;
  if (allowBootstrap && data.used_at_ms && Date.now() - data.used_at_ms <= BOOTSTRAP_GRACE_MS) {
    return true;
  }
  return Boolean(data.used_ip || data.used_ua);
}

function isDocumentRequest(request) {
  const dest = (request.headers.get("sec-fetch-dest") || "").toLowerCase();
  if (dest) return dest === "document";
  const accept = (request.headers.get("accept") || "").toLowerCase();
  return accept.includes("text/html");
}

function getBaseDir(pathname) {
  if (!pathname || pathname === "/") return "/";
  return pathname.endsWith("/") ? pathname : pathname.replace(/\/[^/]*$/, "/");
}

function detectDeviceType(userAgent) {
  const ua = String(userAgent || "").toLowerCase();
  if (/(ipad|tablet|playbook|silk)|(android(?!.*mobile))/i.test(ua)) return "tablet";
  if (/mobile|iphone|ipod|android.*mobile|windows phone/i.test(ua)) return "mobile";
  return "desktop";
}

function isDeviceAllowed(deviceType, allowedDevices) {
  if (!deviceType) return true;
  if (!Array.isArray(allowedDevices) || allowedDevices.length === 0) return true;
  return allowedDevices.includes(deviceType);
}

function appendTokenToUrl(targetUrl, token) {
  try {
    const url = new URL(targetUrl);
    url.searchParams.set("access_token", token);
    return url.toString();
  } catch {
    return targetUrl;
  }
}

function buildWaitingPage(token, data, deviceOk) {
  const startMs = data.start_at_ms || Date.now();
  const isUnscheduled = data.access_policy === "unscheduled";
  const graceUntilMs = data.grace_expires_at_ms || (Date.now() + UNSCHEDULED_GRACE_MS);
  const targetUrl = data.mode === "token"
    ? appendTokenToUrl(data.target_url, token)
    : `/proxy/${token}/`;
  const policyNote = isUnscheduled
    ? "请在 10 分钟内进入实验，仅能启动一次，确认准备好后再进入。进入实验后请勿刷新或重新打开。"
    : "仅能启动一次，请勿刷新页面。进入实验后请勿重新打开。";
  return `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>实验等待中</title>
  <style>
    body { font-family: "Noto Sans SC", sans-serif; background: #f6f7fb; color: #1f2937; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .card { max-width: 520px; background: #fff; border-radius: 20px; padding: 2rem; box-shadow: 0 20px 40px rgba(0,0,0,0.12); text-align: center; }
    .hint { color: #6b7280; font-size: 0.95rem; }
    .timer { font-size: 2rem; font-weight: 700; margin: 1rem 0; }
    .warn { color: #b42318; }
    .primary { border: none; padding: 0.75rem 1.6rem; border-radius: 12px; background: #2563eb; color: #fff; font-weight: 600; cursor: pointer; }
    .primary[disabled] { opacity: 0.6; cursor: not-allowed; }
  </style>
</head>
<body>
  <div class="card">
    <h2>实验即将开始</h2>
    <p class="hint">${policyNote}</p>
    <div class="timer" id="timer">--:--</div>
    <button class="primary" id="startBtn" style="display:${isUnscheduled ? "inline-block" : "none"}">我已准备好，进入实验</button>
    <p class="hint" id="status"></p>
  </div>
  <script>
    const startMs = ${Number(startMs)};
    const isUnscheduled = ${isUnscheduled ? "true" : "false"};
    const graceUntilMs = ${Number(graceUntilMs)};
    const deviceOk = ${deviceOk ? "true" : "false"};
    const targetUrl = ${JSON.stringify(targetUrl)};
    const statusEl = document.getElementById("status");
    const timerEl = document.getElementById("timer");
    const startBtn = document.getElementById("startBtn");

    if (!deviceOk) {
      statusEl.textContent = "当前设备不符合要求，请使用允许的设备打开链接。";
      statusEl.classList.add("warn");
    }

    function format(ms) {
      const s = Math.max(0, Math.floor(ms / 1000));
      const m = Math.floor(s / 60);
      const r = s % 60;
      return String(m) + ":" + String(r).padStart(2, "0");
    }

    function tick() {
      const now = Date.now();
      if (isUnscheduled) {
        const remaining = graceUntilMs - now;
        timerEl.textContent = format(remaining);
        if (remaining <= 0) {
          statusEl.textContent = "已超过可进入时间，请联系主试重新获取链接。";
          statusEl.classList.add("warn");
          if (startBtn) {
            startBtn.disabled = true;
            startBtn.textContent = "链接已过期";
          }
        }
        return;
      }
      const remaining = startMs - now;
      timerEl.textContent = format(remaining);
      if (remaining <= 0 && deviceOk) {
        statusEl.textContent = "正在进入实验...";
        location.href = targetUrl;
      }
    }

    if (startBtn) {
      startBtn.addEventListener("click", async () => {
        if (!deviceOk) return;
        if (Date.now() > graceUntilMs) {
          statusEl.textContent = "已超过可进入时间，请联系主试重新获取链接。";
          statusEl.classList.add("warn");
          return;
        }
        statusEl.textContent = "正在验证...";
        try {
          const resp = await fetch("/token/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token: ${JSON.stringify(token)} }),
          });
          if (!resp.ok) {
            const data = await resp.json().catch(() => ({}));
            statusEl.textContent = data.error || "访问令牌无效";
            statusEl.classList.add("warn");
            return;
          }
          statusEl.textContent = "正在进入实验...";
          location.href = targetUrl;
        } catch {
          statusEl.textContent = "验证失败，请检查网络后重试。";
          statusEl.classList.add("warn");
        }
      });
    }
    tick();
    setInterval(tick, 500);
  </script>
</body>
</html>`;
}

async function handleHostedAsset(request, env, url) {
  if (!env.ASSETS_R2) return new Response("R2 not configured", { status: 500 });
  const parts = url.pathname.split("/").filter(Boolean);
  const prefix = parts[1];
  if (!prefix) return new Response("Not Found", { status: 404 });
  let relPath = parts.slice(2).join("/") || "index.html";
  if (relPath.endsWith("/")) relPath += "index.html";
  if (relPath === "_capture.js") {
    return new Response(buildCaptureScript(), {
      headers: {
        "content-type": "application/javascript; charset=utf-8",
        ...corsHeaders(),
      },
    });
  }

  const accessToken = url.searchParams.get("access_token") || "";
  const tokenData = accessToken ? await getTokenData(env, accessToken) : null;
  if (accessToken && !tokenData) {
    return new Response("Token not found", { status: 404 });
  }
  if (tokenData && tokenData.mode === "proxy") {
    return new Response("Invalid mode", { status: 400 });
  }

  if (tokenData && tokenData.mode === "token") {
    const now = Date.now();
    if (tokenData.expires_at_ms && now > tokenData.expires_at_ms) {
      return new Response("Token expired", { status: 410 });
    }
    if (tokenData.access_policy === "unscheduled" && tokenData.grace_expires_at_ms && now > tokenData.grace_expires_at_ms) {
      return new Response("Grace period expired", { status: 410 });
    }
    const deviceType = detectDeviceType(request.headers.get("user-agent"));
    if (!isDeviceAllowed(deviceType, tokenData.allowed_devices)) {
      return new Response("Device not allowed", { status: 403 });
    }
    const startMs = tokenData.start_at_ms || now;
    if (tokenData.access_policy !== "unscheduled" && now < startMs - 2000) {
      return new Response("Too early", { status: 409 });
    }
    const docRequest = isDocumentRequest(request);
    if (docRequest) {
      if (tokenData.hosted_content_used_at_ms) {
        return new Response("Token already used", { status: 409 });
      }
      const info = getClientInfo(request);
      tokenData.hosted_content_used_at_ms = now;
      tokenData.hosted_content_used_at = new Date().toISOString();
      tokenData.hosted_used_ip = info.ip;
      tokenData.hosted_used_ua = info.ua;
      await saveTokenData(env, accessToken, tokenData);
    }
    if (tokenData.used_at_ms && now > tokenData.used_at_ms + DEFAULT_GRACE_MS) {
      return new Response("Token expired", { status: 410 });
    }
  }
  const accessConfig = tokenData?.access_config || {};
  const downloadPolicy = accessConfig.download_policy
    || (accessConfig.allow_download ? "download_and_upload" : "upload_only");
  const allowDownload = downloadPolicy !== "upload_only";

  const key = `${prefix}/${relPath}`;
  let object = await env.ASSETS_R2.get(key);
  if (!object && env.PSYCHOJS_R2) {
    object = await env.PSYCHOJS_R2.get(relPath);
  }
  if (!object) return new Response("Not Found", { status: 404 });

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("cache-control", "public, max-age=300");
  headers.set("Access-Control-Allow-Origin", "*");

  const contentType = headers.get("content-type") || "";
  const isHtml = contentType.includes("text/html") || relPath.endsWith(".html");
  if (!isHtml) {
    return new Response(object.body, { headers });
  }

  const html = await object.text();
  const injected = injectCaptureScript(html, {
    prefix,
    accessToken,
    allowDownload,
    downloadPolicy,
  });
  headers.set("content-type", "text/html; charset=utf-8");
  return new Response(injected, { headers });
}

function injectCaptureScript(html, { prefix, accessToken, allowDownload, downloadPolicy }) {
  const params = new URLSearchParams({
    prefix: String(prefix || ""),
    token: String(accessToken || ""),
    policy: String(downloadPolicy || "upload_only"),
  });
  const scriptTag = `<script src="/exp/${encodeURIComponent(prefix)}/_capture.js?${params.toString()}"></script>`;
  if (html.includes("</head>")) {
    return html.replace("</head>", `${scriptTag}</head>`);
  }
  return `${html}\n${scriptTag}`;
}

function buildCaptureScript() {
  return `(() => {
  const readConfig = () => {
    const config = window.__EXP_CAPTURE__ || {};
    const current = document.currentScript;
    let prefix = config.prefix || "";
    let accessToken = config.access_token || "";
    let downloadPolicy = config.download_policy || "";
    if (current && current.src) {
      try {
        const srcUrl = new URL(current.src, location.href);
        if (!prefix) prefix = srcUrl.searchParams.get("prefix") || "";
        if (!accessToken) accessToken = srcUrl.searchParams.get("token") || "";
        if (!downloadPolicy) downloadPolicy = srcUrl.searchParams.get("policy") || "";
      } catch {
        // ignore
      }
    }
    if (!prefix) {
      const match = location.pathname.match(/^\/exp\/([^/]+)\//);
      if (match) prefix = match[1];
    }
    if (!accessToken) {
      accessToken = new URLSearchParams(location.search).get("access_token") || "";
    }
    return {
      prefix,
      accessToken,
      downloadPolicy: downloadPolicy || "upload_only",
    };
  };

  const { prefix, accessToken, downloadPolicy } = readConfig();
  const allowDownload = downloadPolicy !== "upload_only";

  const post = (payload) => {
    if (!prefix) return;
    if (downloadPolicy === "download_only") return;
    const body = JSON.stringify({
      prefix,
      access_token: accessToken,
      download_policy: downloadPolicy,
      payload,
    });
    if (navigator.sendBeacon) {
      const blob = new Blob([body], { type: "application/json" });
      navigator.sendBeacon("/data/collect", blob);
      return;
    }
    fetch("/data/collect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      keepalive: true,
    }).catch(() => {});
  };

  const extractPsychoData = () => {
    try {
      const psycho = window.psychoJS || window.psychojs || window.PsychoJS;
      const exp = psycho?.experiment || psycho?._experiment;
      const data = exp?._trialsData || exp?._trialList || null;
      if (data) post({ type: "psychojs_data", data });
    } catch {
      // ignore
    }
  };

  const hookPsychoSave = () => {
    if (window.__EXP_SAVE_HOOKED__) return true;
    const psycho = window.psychoJS || window.psychojs || window.PsychoJS;
    const exp = psycho?.experiment || psycho?._experiment;
    if (!exp || typeof exp.save !== "function") return false;
    const original = exp.save.bind(exp);
    exp.save = async function (...args) {
      let result;
      try {
        if (downloadPolicy === "upload_only") {
          result = undefined;
        } else {
          result = await original(...args);
        }
      } finally {
        try {
          const data = exp._trialsData || exp._trialList || exp._data || null;
          if (data) post({ type: "psychojs_save", data });
        } catch {
          // ignore
        }
      }
      return result;
    };
    window.__EXP_SAVE_HOOKED__ = true;
    return true;
  };

  const blockDownload = () => {
    if (allowDownload) return true;
    if (typeof window.saveAs === "function" && !window.saveAs.__blocked) {
      const original = window.saveAs;
      const blocked = function () {
        post({ type: "download_blocked", ts: Date.now(), source: "saveAs" });
        return undefined;
      };
      blocked.__original = original;
      blocked.__blocked = true;
      window.saveAs = blocked;
    }
    if (typeof navigator.msSaveOrOpenBlob === "function" && !navigator.msSaveOrOpenBlob.__blocked) {
      const originalMs = navigator.msSaveOrOpenBlob;
      navigator.msSaveOrOpenBlob = function () {
        post({ type: "download_blocked", ts: Date.now(), source: "msSaveOrOpenBlob" });
        return false;
      };
      navigator.msSaveOrOpenBlob.__original = originalMs;
      navigator.msSaveOrOpenBlob.__blocked = true;
    }
    if (!window.__EXP_DOWNLOAD_GUARD__) {
      window.__EXP_DOWNLOAD_GUARD__ = true;
      document.addEventListener("click", (event) => {
        const target = event.target?.closest ? event.target.closest("a") : null;
        if (!target) return;
        const href = target.getAttribute("href") || "";
        const hasDownload = target.hasAttribute("download");
        const isBlob = href.startsWith("blob:") || href.startsWith("data:");
        if (hasDownload || isBlob) {
          event.preventDefault();
          post({ type: "download_blocked", ts: Date.now(), source: "anchor", href });
        }
      }, true);

      const originalOpen = window.open;
      window.open = function (url, ...rest) {
        if (typeof url === "string" && (url.startsWith("blob:") || url.startsWith("data:"))) {
          post({ type: "download_blocked", ts: Date.now(), source: "window.open", href: url });
          return null;
        }
        return originalOpen.call(window, url, ...rest);
      };
    }
    return Boolean(window.saveAs && window.saveAs.__blocked);
  };

  if (prefix) {
    post({ type: "capture_loaded", ts: Date.now() });
  }

  window.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") extractPsychoData();
  });
  window.addEventListener("beforeunload", extractPsychoData);

  const hookTimer = setInterval(() => {
    if (hookPsychoSave()) {
      clearInterval(hookTimer);
    }
  }, 500);

  const blockTimer = setInterval(() => {
    if (blockDownload()) {
      clearInterval(blockTimer);
    }
  }, 500);
})();`;
}

async function handleDataCollect(request, env) {
  if (!env.DATA_R2) return json({ error: "DATA_R2 not configured" }, 500);
  const text = await request.text();
  let data = {};
  try {
    data = JSON.parse(text || "{}") || {};
  } catch {
    data = {};
  }
  const prefix = String(data.prefix || "").trim();
  if (!prefix) return json({ error: "Missing prefix" }, 400);
  const accessToken = String(data.access_token || "").trim();
  const safeToken = accessToken.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 120) || "anonymous";
  const rand = crypto.getRandomValues(new Uint8Array(6));
  const suffix = Array.from(rand, (b) => b.toString(16).padStart(2, "0")).join("");
  const key = `${prefix}/${safeToken}/${Date.now()}_${suffix}.json`;
  const payload = {
    received_at: new Date().toISOString(),
    ip: request.headers.get("cf-connecting-ip") || "",
    user_agent: request.headers.get("user-agent") || "",
    ...data,
  };
  await env.DATA_R2.put(key, JSON.stringify(payload), {
    httpMetadata: { contentType: "application/json" },
  });
  return json({ ok: true, key });
}

async function handleAccessPage(request, env, token) {
  if (!token) return new Response("Missing token", { status: 400, headers: corsHeaders() });
  const data = await getTokenData(env, token);
  if (!data) return new Response("Token not found", { status: 404, headers: corsHeaders() });

  const now = Date.now();
  if (data.expires_at_ms && now > data.expires_at_ms) {
    return new Response("Token expired", { status: 410, headers: corsHeaders() });
  }
  if (data.access_policy === "unscheduled") {
    if (!data.grace_expires_at_ms || now > data.grace_expires_at_ms) {
      data.grace_expires_at_ms = now + UNSCHEDULED_GRACE_MS;
      await saveTokenData(env, token, data);
    }
  }

  const deviceType = detectDeviceType(request.headers.get("user-agent"));
  const deviceOk = isDeviceAllowed(deviceType, data.allowed_devices);

  const html = buildWaitingPage(token, data, deviceOk);
  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", ...corsHeaders() },
  });
}

async function handleTokenVerify(request, env) {
  const payload = await request.json().catch(() => ({}));
  const token = payload?.token;
  if (!token) return json({ error: "Missing token" }, 400);

  const data = await getTokenData(env, token);
  if (!data) return json({ error: "Token not found" }, 404);

  const now = Date.now();
  if (data.expires_at_ms && now > data.expires_at_ms) {
    return json({ error: "Token expired" }, 410);
  }
  if (data.access_policy === "unscheduled" && data.grace_expires_at_ms && now > data.grace_expires_at_ms) {
    return json({ error: "Grace period expired" }, 410);
  }

  const deviceType = detectDeviceType(request.headers.get("user-agent"));
  if (!isDeviceAllowed(deviceType, data.allowed_devices)) {
    return json({ error: "Device not allowed" }, 403);
  }

  const startMs = data.start_at_ms || now;
  if (data.access_policy !== "unscheduled" && now < startMs - 2000) {
    return json({ error: "Too early", start_at_ms: startMs }, 409);
  }
  const sessionId = getSessionId(request);

  if (data.mode === "token") {
    if (data.hosted_content_used_at_ms) {
      return json({ error: "Token already used" }, 409);
    }
    if (data.access_config?.hosted) {
      return json({ ok: true, start_at_ms: startMs });
    }
    if (data.used_at_ms) {
      return json({ error: "Token already used" }, 409);
    }
    data.used_at_ms = now;
    data.used_at = new Date().toISOString();
    await saveTokenData(env, token, data);
    return json({ ok: true, start_at_ms: startMs });
  }

  if (data.mode === "proxy" && data.used_at_ms) {
    if (!isSameClient(data, sessionId, request, true)) {
      return json({ error: "Token already used" }, 409);
    }
    if (now > data.used_at_ms + DEFAULT_GRACE_MS) {
      return json({ error: "Token expired" }, 410);
    }
  }

  return json({ ok: true, start_at_ms: startMs });
}

async function handleTokenStatus(request, env, token) {
  if (!token) return json({ error: "Missing token" }, 400);
  const data = await getTokenData(env, token);
  if (!data) return json({ error: "Token not found" }, 404);
  return json({ ok: true, data });
}

async function handleProxy(request, env, token, restPath, search) {
  if (!token) return new Response("Missing token", { status: 400, headers: corsHeaders() });
  const data = await getTokenData(env, token);
  if (!data) return new Response("Token not found", { status: 404, headers: corsHeaders() });
  if (data.mode !== "proxy") return new Response("Invalid mode", { status: 400, headers: corsHeaders() });

  const now = Date.now();
  if (data.expires_at_ms && now > data.expires_at_ms) {
    return new Response("Token expired", { status: 410, headers: corsHeaders() });
  }
  if (data.access_policy === "unscheduled" && data.grace_expires_at_ms && now > data.grace_expires_at_ms) {
    return new Response("Grace period expired", { status: 410, headers: corsHeaders() });
  }

  const deviceType = detectDeviceType(request.headers.get("user-agent"));
  if (!isDeviceAllowed(deviceType, data.allowed_devices)) {
    return new Response("Device not allowed", { status: 403, headers: corsHeaders() });
  }

  const startMs = data.start_at_ms || now;
  if (data.access_policy !== "unscheduled" && now < startMs) {
    return new Response("Not started", { status: 409, headers: corsHeaders() });
  }

  const existingSessionId = getSessionId(request);
  let activeSessionId = existingSessionId;
  let shouldSetSession = false;
  if (!activeSessionId) {
    activeSessionId = createSessionId();
    shouldSetSession = true;
  }

  const docRequest = isDocumentRequest(request);
  if (data.used_at_ms) {
    const sameClient = isSameClient(data, existingSessionId, request, true);
    if (!sameClient && docRequest) {
      return new Response("Token already used", { status: 409, headers: corsHeaders() });
    }
    if (now > data.used_at_ms + DEFAULT_GRACE_MS) {
      return new Response("Token expired", { status: 410, headers: corsHeaders() });
    }
    if (!existingSessionId && shouldSetSession) {
      data.used_session_id = activeSessionId;
      await saveTokenData(env, token, data);
    }
  } else {
    const info = getClientInfo(request);
    data.used_at_ms = now;
    data.used_at = new Date().toISOString();
    data.used_session_id = activeSessionId;
    data.used_ip = info.ip;
    data.used_ua = info.ua;
    await saveTokenData(env, token, data);
  }

  const targetBase = new URL(data.target_url);
  const targetPath = restPath ? `/${restPath}` : targetBase.pathname;
  const targetUrl = new URL(targetPath + (search || ""), targetBase.origin);
  const baseDir = getBaseDir(targetBase.pathname);
  const proxyOrigin = new URL(request.url).origin;
  const proxyBase = `${proxyOrigin}/proxy/${token}`;
  const proxyDirBase = `${proxyBase}${baseDir}`;

  const init = {
    method: request.method,
    headers: request.headers,
    body: request.body,
    redirect: "manual",
  };

  const resp = await fetch(targetUrl.toString(), init);
  const contentType = resp.headers.get("content-type") || "";
  const headers = new Headers(resp.headers);
  headers.set("access-control-allow-origin", "*");
  if (shouldSetSession) {
    const isSecure = new URL(request.url).protocol === "https:";
    const maxAge = Math.max(60, Math.floor(DEFAULT_GRACE_MS / 1000));
    headers.append(
      "set-cookie",
      `access_session=${encodeURIComponent(activeSessionId)}; Path=/proxy/${token}/; Max-Age=${maxAge}; SameSite=Lax${isSecure ? "; Secure" : ""}`
    );
  }

  if (contentType.includes("text/html")) {
    let text = await resp.text();
    if (!/\<base\s/i.test(text)) {
      text = text.replace(/<head(\b[^>]*)>/i, `<head$1><base href="${proxyDirBase}">`);
    }
    text = text
      .replace(/(href|src|action)=(['"])\/(?!\/)([^'">]*)/g, (match, attr, quote, path) => `${attr}=${quote}${proxyBase}/${path}`)
      .replace(
        /(href|src|action)=(['"])(?!https?:|\/|#|data:|mailto:|tel:|javascript:)([^'">]+)/g,
        (match, attr, quote, path) => `${attr}=${quote}${proxyDirBase}${path}`
      );
    return new Response(text, { status: resp.status, headers });
  }

  return new Response(resp.body, { status: resp.status, headers });
}
