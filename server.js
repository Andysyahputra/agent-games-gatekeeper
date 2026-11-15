// server.js — local dev server (plain node http, no framework).
//   AGENT_GAMES_HMAC_SECRET=test-only-secret-for-local-testing node server.js
// Listens on PORT (default 3000). Same handler as the Vercel function.
"use strict";
const http = require("node:http");
const { handleRequest } = require("./lib/handler");

const PORT = Number(process.env.PORT || 3000);

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);
    try {
      const out = await handleRequest(req.method, rawBody, req.headers);
      res.writeHead(out.status, out.headers);
      res.end(out.body);
    } catch (e) {
      console.error("gatekeeper error:", e);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`gatekeeper listening on http://127.0.0.1:${PORT}`);
  console.log(`HMAC secret configured: ${!!process.env.AGENT_GAMES_HMAC_SECRET}`);
  console.log(`Kurier key configured: ${!!process.env.KURIER_API_KEY}`);
});
