// api/index.js — Vercel serverless entrypoint. Thin wrapper over lib/handler.
"use strict";
const { handleRequest } = require("../lib/handler");

module.exports = async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  const headers = {};
  for (const [k, v] of Object.entries(req.headers || {})) headers[k.toLowerCase()] = v;
  try {
    const out = await handleRequest(req.method, rawBody, headers);
    res.writeHead(out.status, out.headers);
    res.end(out.body);
  } catch (e) {
    console.error("gatekeeper error:", e);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "internal_error" }));
  }
};
