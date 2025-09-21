// api/verify.js — EDGE runtime
export const config = { runtime: "edge" };

const textEncoder = new TextEncoder();

const b64uToUint8 = (b64u) => {
  b64u = b64u.replaceAll("-", "+").replaceAll("_", "/");
  const pad = b64u.length % 4 ? 4 - (b64u.length % 4) : 0;
  const b64 = b64u + "=".repeat(pad);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const b64uToJSON = (b64u) => JSON.parse(new TextDecoder().decode(b64uToUint8(b64u)));

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type, authorization",
      "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
      pragma: "no-cache",
      expires: "0",
    },
  });
}

async function verifyHS256(secret, signingInput, signatureB64u) {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sig = b64uToUint8(signatureB64u);
  return crypto.subtle.verify("HMAC", key, sig, textEncoder.encode(signingInput));
}

function getWrappedToken(req) {
  const url = new URL(req.url);
  const q = url.searchParams.get("token") || url.searchParams.get("t");
  return q || null;
}

export default async function handler(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204 });

  const JWT_SECRET = "hR8%Zp@1Qx#sK7!vLm4nBt$2Dy&Wj9^CgUf0*Xh6oPi3rYe+Aq5vMz7wNl8RbT";

  let wrapped = getWrappedToken(req);
  if (!wrapped && req.method !== "GET") {
    try {
      const body = await req.json();
      wrapped = body?.token || null;
    } catch {}
  }
  if (!wrapped) return jsonResponse({ ok: false, error: "missing token" }, 400);

  try {
    const jwt = atob(wrapped);
    const [hB64u, pB64u, sB64u] = jwt.split(".");
    if (!hB64u || !pB64u || !sB64u) return jsonResponse({ ok: false, error: "malformed jwt" }, 401);

    const signingInput = `${hB64u}.${pB64u}`;
    const valid = await verifyHS256(JWT_SECRET, signingInput, sB64u);
    if (!valid) return jsonResponse({ ok: false, error: "invalid signature" }, 401);

    const header = b64uToJSON(hB64u);
    const payload = b64uToJSON(pB64u);

    const now = Math.floor(Date.now() / 1000);
    if (payload?.exp && now >= payload.exp) {
      return jsonResponse({ ok: false, error: "token expired", payload }, 401);
    }

    return jsonResponse({ ok: true, header, payload });
  } catch (e) {
    return jsonResponse({ ok: false, error: e?.message || "verify failed" }, 401);
  }
}
