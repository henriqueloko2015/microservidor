const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const app = express();

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET_KEY = process.env.SECRET_KEY;
const DOMINIO = process.env.DOMINIO; // ex: bb-bet.top

function join(a, b) { return Buffer.concat([a, b]); }

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function decryptToken(tokenBase64) {
  try {
    const raw = Buffer.from(tokenBase64, 'base64');
    const hmac = raw.slice(0, 32);
    const iv = raw.slice(32, 48);
    const data = raw.slice(48);
    const key = crypto.createHash('sha256').update(SECRET_KEY).digest();
    const expectedHmac = crypto.createHmac('sha256', SECRET_KEY)
      .update(join(iv, data))
      .digest();
    if (!timingSafeEqual(hmac, expectedHmac)) return null;

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(data);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return JSON.parse(decrypted.toString('utf8'));
  } catch (err) {
    console.error("Erro ao decifrar token:", err.message);
    return null;
  }
}

// ------------------------------------
// NOVA FUNÇÃO ANTI-LEECH COM LOGS
// ------------------------------------
function checkReferer(req) {
  const referer = req.headers.referer || '';

  console.log("=== REFERER DEBUG ===");
  console.log("Referer recebido:", referer);
  console.log("DOMINIO permitido:", DOMINIO);

  if (!referer) {
    console.log("Sem referer → permitido");
    return true;
  }

  try {
    const url = new URL(referer);
    console.log("Host extraído:", url.hostname);

    if (url.hostname === DOMINIO || url.hostname.endsWith("." + DOMINIO)) {
      console.log("Referer permitido ✔");
      return true;
    }

    console.log("Referer bloqueado ✖");
    return false;

  } catch (err) {
    console.log("Erro ao analisar referer:", err.message);
    return false;
  }
}

// ------------------------------------
// ROTA PRINCIPAL
// ------------------------------------
app.get('/', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("Token faltando");

  if (!checkReferer(req)) {
    return res.status(403).send("Acesso bloqueado (Referer inválido)");
  }

  const payload = decryptToken(token);
  if (!payload) return res.status(403).send("Token inválido");

  if (Date.now() / 1000 > payload.exp) {
    return res.status(410).send("Token expirado");
  }

  const videoUrl = payload.url;

  try {
    const headers = {};
    if (req.headers.range) headers['Range'] = req.headers.range;

    headers['Referer'] = `https://${DOMINIO}/`;
    headers['User-Agent'] = req.headers['user-agent'] || 'Mozilla/5.0';

    const upstream = await fetch(videoUrl, { headers });

    const resHeaders = {};
    upstream.headers.forEach((v, k) => {
      if (!['connection', 'transfer-encoding', 'content-encoding'].includes(k.toLowerCase()))
        resHeaders[k] = v;
    });

    resHeaders['Accept-Ranges'] = 'bytes';
    resHeaders['Access-Control-Allow-Origin'] = '*';
    resHeaders['Cache-Control'] = 'no-store';

    res.status(upstream.status);
    upstream.body.pipe(res);

  } catch (err) {
    console.error("Erro no proxy:", err.message);
    res.status(500).send("Erro no proxy: " + err.message);
  }
});

app.listen(PORT, () => {
  console.log(`Microservidor rodando em http://localhost:${PORT}`);
  console.log(`DOMINIO permitido: ${DOMINIO}`);
});


