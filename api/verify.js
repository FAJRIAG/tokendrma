// api/verify.js
import jwt from "jsonwebtoken";

function getWrappedToken(req) {
  // urutan prioritas: body.token -> query.token -> query.t -> Authorization: Bearer
  if (req.body && typeof req.body === "object" && req.body.token) return req.body.token;
  if (req.query && (req.query.token || req.query.t)) return req.query.token || req.query.t;

  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

export default function handler(req, res) {
  const { JWT_SECRET = "GANTI_DENGAN_SECRET_YANG_KUAT" } = process.env;

  const wrapped = getWrappedToken(req);
  if (!wrapped) {
    return res.status(400).json({ ok: false, error: "missing token (send in body.token, query.token, or Authorization: Bearer)" });
  }

  try {
    // decode base64 -> JWT string "header.payload.signature"
    const jwtStr = Buffer.from(String(wrapped), "base64").toString("utf8");

    // verifikasi signature & expiry
    const payload = jwt.verify(jwtStr, JWT_SECRET);

    // untuk pengecekan/debug tambahan, bisa tampilkan header-nya juga
    const [h] = jwtStr.split(".");
    const header = JSON.parse(Buffer.from(h, "base64").toString("utf8"));

    return res.status(200).json({ ok: true, header, payload });
  } catch (e) {
    return res.status(401).json({ ok: false, error: e.message });
  }
}
