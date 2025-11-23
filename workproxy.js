// ========================================================
// Worker compatível 100% com AES-256-CBC + HMAC SHA-256 do PHP
// Token de longa duração e streaming contínuo
// ========================================================
export default {
  async fetch(request, env) {

    const SECRET_KEY = env.SECRET_KEY;
    const DOMINIO = env.DOMINIO;

    const url = new URL(request.url);
    const token = url.searchParams.get("token");
    if (!token) return new Response("Token faltando", { status: 400 });

    // -------------------------------
    // ANTI-LEECH
    // -------------------------------
    const referer = request.headers.get("Referer") || "";
    if (!referer.includes(DOMINIO)) {
      return new Response("Acesso negado", { status: 403 });
    }

    try {
      // -------------------------------
      // DECODIFICA BASE64 → Uint8Array
      // -------------------------------
      const raw = Uint8Array.from(atob(token), c => c.charCodeAt(0));

      const hmac = raw.slice(0, 32);
      const iv   = raw.slice(32, 48);
      const data = raw.slice(48);

      const enc = new TextEncoder();
      const keyData = enc.encode(SECRET_KEY);

      // -------------------------------
      // VERIFICA HMAC
      // -------------------------------
      const hmacKey = await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      );

      const signed = new Uint8Array(
        await crypto.subtle.sign("HMAC", hmacKey, join(iv, data))
      );

      if (!timingSafeEqual(hmac, signed)) {
        return new Response("Token inválido", { status: 403 });
      }

      // -------------------------------
      // AES-256-CBC DECRYPT
      // -------------------------------
      const aesKey = await crypto.subtle.importKey(
        "raw",
        await crypto.subtle.digest("SHA-256", keyData),
        { name: "AES-CBC" },
        false,
        ["decrypt"]
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        aesKey,
        data
      );

      const payload = JSON.parse(new TextDecoder().decode(decrypted));

      // -------------------------------
      // VERIFICA EXPIRAÇÃO (LONGA DURAÇÃO)
      // -------------------------------
      if (Date.now() / 1000 > payload.exp) {
        return new Response("Token expirado", { status: 410 });
      }

      const videoUrl = payload.url;

      // -------------------------------
      // PROXY STREAMING COM RANGE REQUESTS
      // -------------------------------
      const rangeHeader = request.headers.get("Range");
      const fetchHeaders = rangeHeader ? { "Range": rangeHeader } : request.headers;

      const upstream = await fetch(videoUrl, {
        headers: fetchHeaders,
        method: request.method,
        redirect: "follow"
      });

      const headers = new Headers(upstream.headers);
      headers.set("Accept-Ranges", "bytes");
      headers.set("Access-Control-Allow-Origin", "*");
      headers.set("Cache-Control", "no-store");
      headers.set("X-Accel-Buffering", "no");

      return new Response(upstream.body, {
        status: upstream.status,
        headers
      });

    } catch (err) {
      return new Response("Token corrupto", { status: 400 });
    }
  }
};

// ========================================================
// Funções auxiliares
// ========================================================
function join(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a[i] ^ b[i];
  return out === 0;
}
