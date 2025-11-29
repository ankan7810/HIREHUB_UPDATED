
import jwt from "jsonwebtoken";

const authenticateToken = (req, res, next) => {
  try {
    let token = req.cookies?.token || req.headers?.authorization;

    if (!token) return res.status(401).json({ message: "No token provided", success: false });

    if (typeof token === "string" && token.toLowerCase().startsWith("bearer ")) {
      token = token.split(" ")[1];
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error("JWT verify error:", err);
        return res.status(401).json({ message: "Invalid or expired token", success: false });
      }

      // Normalize common id claim locations
      const id =
        decoded?.userId ??
        decoded?.id ??
        decoded?.sub ??
        decoded?.user?.id ??
        (typeof decoded === "string" ? decoded : null);

      if (!id) {
        console.warn("Token decoded but no id claim found:", decoded);
        return res.status(401).json({ message: "Invalid token payload", success: false });
      }

      // Attach for downstream handlers (keep both names if you used req.id elsewhere)
      req.id = id;
      req.userId = id;
      req.user = decoded; // optional: full payload if you need more claims

      return next();
    });
  } catch (error) {
    console.error("Auth middleware error:", error);
    return res.status(500).json({ message: "Authentication error", success: false });
  }
};

export default authenticateToken;
