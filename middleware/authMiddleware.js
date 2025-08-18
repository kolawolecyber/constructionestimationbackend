const jwt = require("jsonwebtoken");

const requireAuth = (req, res, next) => {
  try {
    let token = req.cookies?.jwt;
    if (!token && req.headers.authorization?.startsWith("Bearer ")) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({ message: "Not authorized, token missing" });
    }

    // ✅ Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "Jwt_token");

    // Attach decoded user data
    req.user = decoded;

    next();
  } catch (err) {
    console.error("JWT verification failed:", err.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

module.exports = { requireAuth };
