// api/verify.js
import jwt from "jsonwebtoken";

function getWrappedToken(req) {
  if (req.body && typeof req.body === "object" && req.body.token) return req.body.token;
  if (req.query && (req.query.token || req.query.t)) return req.query.token || req.query.t;
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

export default function handler(req, res) {
  // CORS + NO-CACHE
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  if (req.method === "OPTIONS") return res.status(204).end();

  const { JWT_SECRET = "GANTI_DENGAN_SECRET_YANG_KUAT" } = process.env;

  const wrapped = getWrappedToken(req);
  if (!wrapped) return res.status(400).json({ ok: false, error: "missing token" });

  try {
    // base64 -> JWT string
    const jwtStr = Buffer.from(String(wrapped), "base64").toString("utf8");
    // verifikasi
    const payload = jwt.verify(jwtStr, JWT_SECRET);
    // header opsional untuk debug
    const [h] = jwtStr.split(".");
    const header = JSON.parse(Buffer.from(h, "base64").toString("utf8"));
    return res.status(200).json({ ok: true, header, payload });
  } catch (e) {
    return res.status(401).json({ ok: false, error: e.message });
  }
}
