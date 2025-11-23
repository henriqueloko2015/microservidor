const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const app = express();
const port = process.env.PORT || 3000;

// Variáveis de Ambiente (Mantenha as mesmas do seu Worker)
// **IMPORTANTE**: Substitua pelos seus valores reais ou use variáveis de ambiente do seu host.
const SECRET_KEY = process.env.SECRET_KEY || "ChaveNovaSeguraAki2025!";
const DOMINIO = process.env.DOMINIO || "microservidor.onrender.com"; // Domínio do seu player (para anti-leech)

// ========================================================
// Funções Auxiliares de Criptografia (Compatíveis com PHP)
// ========================================================

/**
 * Verifica se dois buffers são iguais de forma segura contra ataques de tempo.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    return crypto.timingSafeEqual(a, b);
}

/**
 * Decifra o token encriptado pelo PHP (AES-256-CBC + HMAC SHA-256).
 * @param {string} tokenBase64 - O token completo em Base64.
 * @returns {object|null} O payload decifrado ou null em caso de falha.
 */
function decryptToken(tokenBase64) {
    try {
        // 1. Decodifica Base64
        const raw = Buffer.from(tokenBase64, 'base64');

        // 2. Separa as partes
        const hmac = raw.slice(0, 32); // 32 bytes
        const iv = raw.slice(32, 48); // 16 bytes
        const cipherText = raw.slice(48); // Restante é o texto cifrado

        // 3. Gera a chave AES e a chave HMAC (SHA-256 da SECRET_KEY)
        const key = crypto.createHash('sha256').update(SECRET_KEY).digest();
        
        // 4. Verifica HMAC
        const hmacData = Buffer.concat([iv, cipherText]);
        const expectedHmac = crypto.createHmac('sha256', SECRET_KEY).update(hmacData).digest();

        if (!timingSafeEqual(hmac, expectedHmac)) {
            console.error("HMAC inválido.");
            return null;
        }

        // 5. Decifra AES-256-CBC
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(cipherText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        // 6. Retorna o payload JSON
        const payload = JSON.parse(decrypted.toString('utf8'));
        return payload;

    } catch (err) {
        console.error("Erro ao decifrar token:", err.message);
        return null;
    }
}

// ========================================================
// Rota Principal do Microservidor
// ========================================================

app.get('/', async (req, res) => {
    const token = req.query.token;
    if (!token) {
        return res.status(400).send("Token faltando");
    }

    // -------------------------------
    // ANTI-LEECH
    // -------------------------------
    const referer = req.headers.referer || "";
    // O referer pode incluir o protocolo (http:// ou https://), então verificamos se o domínio está contido.
    if (!referer.includes(DOMINIO)) {
        return res.status(403).send("Acesso negado (Anti-leech)");
    }

    // -------------------------------
    // DECRIPTAÇÃO E VALIDAÇÃO
    // -------------------------------
    const payload = decryptToken(token);

    if (!payload) {
        return res.status(403).send("Token inválido ou corrupto");
    }

    // -------------------------------
    // VERIFICA EXPIRAÇÃO
    // -------------------------------
    if (Date.now() / 1000 > payload.exp) {
        return res.status(410).send("Token expirado");
    }

    const videoUrl = payload.url;

    // -------------------------------
    // PROXY STREAMING COM RANGE REQUESTS
    // -------------------------------
    try {
        const rangeHeader = req.headers.range;
        
        // Configura os headers para a requisição upstream
        const fetchHeaders = {
            // Passa o Range header para o servidor de origem
            ...(rangeHeader && { 'Range': rangeHeader }),
            // Você pode querer passar outros headers, como User-Agent, se necessário
        };

        const upstreamResponse = await axios({
            method: 'get',
            url: videoUrl,
            headers: fetchHeaders,
            responseType: 'stream', // Importante para streaming
        });

        // -------------------------------
        // CONFIGURA HEADERS DE RESPOSTA
        // -------------------------------
        
        // Copia os headers do upstream para a resposta do microservidor
        Object.keys(upstreamResponse.headers).forEach(key => {
            // Evita headers que podem causar problemas ou que serão definidos abaixo
            if (!['connection', 'transfer-encoding', 'content-encoding'].includes(key.toLowerCase())) {
                res.setHeader(key, upstreamResponse.headers[key]);
            }
        });

        // Headers de segurança e compatibilidade
        res.setHeader("Accept-Ranges", "bytes");
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("X-Accel-Buffering", "no"); // Para Nginx/Proxy

        // Define o status code (200, 206, etc.)
        res.status(upstreamResponse.status);

        // Faz o pipe do stream do upstream para a resposta do cliente
        upstreamResponse.data.pipe(res);

    } catch (error) {
        console.error("Erro no proxy de streaming:", error.message);
        // Tenta repassar o status code do erro upstream, se disponível
        const status = error.response ? error.response.status : 500;
        res.status(status).send(`Erro no proxy: ${error.message}`);
    }
});

app.listen(port, () => {
    console.log(`Microservidor de streaming rodando em http://localhost:${port}`);
    console.log(`SECRET_KEY: ${SECRET_KEY}`);
    console.log(`DOMINIO (Anti-leech): ${DOMINIO}`);
});



