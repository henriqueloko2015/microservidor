const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const app = express();
const port = process.env.PORT || 3000;

// Variáveis de Ambiente
const SECRET_KEY = process.env.SECRET_KEY || "ChaveNovaSeguraAki2025!";
const DOMINIOS = (process.env.DOMINIOS || "apicdn.bb-bet.top").split(","); // Pode adicionar múltiplos domínios separados por vírgula

// ================================
// Funções Auxiliares de Criptografia
// ================================

function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function decryptToken(tokenBase64) {
    try {
        const raw = Buffer.from(tokenBase64, 'base64');
        const hmac = raw.slice(0, 32);
        const iv = raw.slice(32, 48);
        const cipherText = raw.slice(48);
        const key = crypto.createHash('sha256').update(SECRET_KEY).digest();

        const expectedHmac = crypto.createHmac('sha256', SECRET_KEY)
            .update(Buffer.concat([iv, cipherText]))
            .digest();

        if (!timingSafeEqual(hmac, expectedHmac)) {
            console.error("HMAC inválido.");
            return null;
        }

        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
        return JSON.parse(decrypted.toString('utf8'));

    } catch (err) {
        console.error("Erro ao decifrar token:", err.message);
        return null;
    }
}

// ================================
// Rota Principal
// ================================

app.get('/', async (req, res) => {
    const token = req.query.token;
    if (!token) return res.status(400).send("Token faltando");

    // -------------------------------
    // ANTI-LEECH
    // -------------------------------
    const referer = req.headers.referer || "";
    const allow = DOMINIOS.some(dom => referer.includes(dom));
    if (!allow) {
        return res.status(403).send("Acesso negado (Anti-leech)");
    }

    // -------------------------------
    // DECRIPTAÇÃO E VALIDAÇÃO
    // -------------------------------
    const payload = decryptToken(token);
    if (!payload) return res.status(403).send("Token inválido ou corrupto");

    if (Date.now() / 1000 > payload.exp) return res.status(410).send("Token expirado");

    const videoUrl = payload.url;

    // -------------------------------
    // PROXY STREAMING COM RANGE REQUESTS
    // -------------------------------
    try {
        const rangeHeader = req.headers.range;
        const headers = { ...(rangeHeader && { Range: rangeHeader }) };

        const upstreamResponse = await axios({
            method: 'get',
            url: videoUrl,
            headers,
            responseType: 'stream',
        });

        Object.keys(upstreamResponse.headers).forEach(key => {
            if (!['connection', 'transfer-encoding', 'content-encoding'].includes(key.toLowerCase())) {
                res.setHeader(key, upstreamResponse.headers[key]);
            }
        });

        res.setHeader("Accept-Ranges", "bytes");
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("X-Accel-Buffering", "no");

        res.status(upstreamResponse.status);
        upstreamResponse.data.pipe(res);

    } catch (error) {
        console.error("Erro no proxy de streaming:", error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).send(`Erro no proxy: ${error.message}`);
    }
});

app.listen(port, () => {
    console.log(`Microservidor de streaming rodando em http://localhost:${port}`);
    console.log(`SECRET_KEY: ${SECRET_KEY}`);
    console.log(`DOMINIOS permitidos (Anti-leech): ${DOMINIOS.join(", ")}`);
});
