import express from 'express';
import crypto from 'crypto';
import fetch from 'node-fetch';

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET_KEY = process.env.SECRET_KEY;
const DOMINIO = process.env.DOMINIO; // ex: bb-bet.top

// -------------------------
// Funções auxiliares
// -------------------------
function join(a, b) {
  return Buffer.concat([a, b]);
}

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

// -------------------------
// NOVA PROTEÇÃO ANTI-LEECH
// -------------------------
function checkReferer(req) {
  const referer = req.headers.referer || '';

  // Sem referer (apps, players externos)
  if (!referer) return true;

  try {
    const url = new URL(referer);

    // permite qualquer subdomínio do seu domínio
    if (url.hostname.endsWith(DOMINIO)) return true;

    return false;
  } catch {
    return false;
  }
}

// -------------------------
// Rota principal
// -------------------------
app.get('/', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("Token faltando");

  if (!checkReferer(req)) {
    return res.status(403).send("Acesso bloqueado (Referer inválido)");
  }

  const payload = decryptToken(token);
  if (!payload) return res.status(403).send("Token inválido");

  // Expiração
  if (Date.now() / 1000 > payload.exp) {
    return res.status(410).send("Token expirado");
  }

  const videoUrl = payload.url;

  try {
    const headers = {};

    if (req.headers.range) headers['Range'] = req.headers.range;

    headers['Referer'] = `https://${DOMINIO}/`;
    headers['User-Agent'] = req.headers['user-agent'] || 'Mozilla/5.0';

    const upstream = await fetch(videoUrl, { headers, method: 'GET' });

    const resHeaders = {};
    upstream.headers.forEach((v, k) => {
      if (!['connection', 'transfer-encoding', 'content-encoding'].includes(k.toLowerCase()))
        resHeaders[k] = v;
    });

    resHeaders['Accept-Ranges'] = 'bytes';
    resHeaders['Access-Control-Allow-Origin'] = '*';
    resHeaders['Cache-Control'] = 'no-store';
    resHeaders['X-Accel-Buffering'] = 'no';

    res.status(upstream.status);
    upstream.body.pipe(res);

  } catch (err) {
    console.error("Erro no proxy:", err.message);
    res.status(500).send(`Erro no proxy: ${err.message}`);
  }
});

app.listen(PORT, () => {
  console.log(`Microservidor rodando em http://localhost:${PORT}`);
  console.log(`DOMINIO: ${DOMINIO}`);
});
