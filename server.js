import express from 'express';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET_KEY = process.env.SECRET_KEY;
const DOMINIO = process.env.DOMINIO; // ex: apicdn.bb-bet.top

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

    // Verifica HMAC
    const expectedHmac = crypto
      .createHmac('sha256', SECRET_KEY)
      .update(join(iv, data))
      .digest();

    if (!timingSafeEqual(hmac, expectedHmac)) return null;

    // Decripta AES-256-CBC
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
// Rota principal
// -------------------------
app.get('/', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("Token faltando");

  // Anti-leech
  const referer = req.headers.referer || '';
  if (!referer.includes(DOMINIO)) {
    return res.status(403).send("Acesso negado");
  }

  const payload = decryptToken(token);
  if (!payload) return res.status(403).send("Token inválido ou corrupto");

  // Expiração
  if (Date.now() / 1000 > payload.exp) {
    return res.status(410).send("Token expirado");
  }

  const videoUrl = payload.url;

  try {
    // Headers que o servidor upstream espera
    const headers = {};
    if (req.headers.range) headers['Range'] = req.headers.range;
    headers['Referer'] = `https://${DOMINIO}/`;
    headers['User-Agent'] = req.headers['user-agent'] || 'Mozilla/5.0';

    // fetch nativo do Node 22 (SEM node-fetch)
    const upstream = await fetch(videoUrl, {
      headers,
      method: 'GET'
    });

    // Copiar headers
    const resHeaders = {};
    upstream.headers.forEach((v, k) => {
      if (!['connection', 'transfer-encoding', 'content-encoding'].includes(k.toLowerCase())) {
        resHeaders[k] = v;
      }
    });

    resHeaders['Accept-Ranges'] = 'bytes';
    resHeaders['Access-Control-Allow-Origin'] = '*';
    resHeaders['Cache-Control'] = 'no-store';
    resHeaders['X-Accel-Buffering'] = 'no';

    res.writeHead(upstream.status, resHeaders);

    // Pipe do streaming
    const reader = upstream.body.getReader();
    const writer = res;

    function pump() {
      return reader.read().then(({ done, value }) => {
        if (done) {
          writer.end();
          return;
        }
        writer.write(Buffer.from(value));
        return pump();
      });
    }

    pump();

  } catch (err) {
    console.error("Erro no proxy:", err.message);
    res.status(500).send(`Erro no proxy: ${err.message}`);
  }
});

app.listen(PORT, () => {
  console.log(`Microservidor rodando em http://localhost:${PORT}`);
  console.log(`DOMINIO: ${DOMINIO}`);
});
