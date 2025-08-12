const jwt = require("jsonwebtoken");
const User = require("../models/User"); // import your user model

const requireAuth = (req, res, next) => {
  // 1. Get token from cookies or Authorization header
  let token = req.cookies?.jwt;
  if (!token && req.headers.authorization?.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  }

  // 2. If no token, block access
  if (!token) {
    return res.status(401).json({ message: "Not authorized" });
  }

  // 3. Verify token
  jwt.verify(token, process.env.JWT_SECRET || "Jwt_token", (err, decodedToken) => {
    if (err) {
      console.log("Token verification error:", err.message);
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decodedToken; // so routes can access user
    next();
  });
};


const checkUser = async (req, res, next) => {
  let token = req.cookies?.jwt;
  if (!token && req.headers.authorization?.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    res.locals.user = null;
    return next();
  }

  jwt.verify(token, process.env.JWT_SECRET || "Jwt_token", async (err, decodedToken) => {
    if (err) {
      console.log("Token verification error:", err.message);
      res.locals.user = null;
      return next();
    }
    try {
      let user = await User.findById(decodedToken.id).select("-password");
      res.locals.user = user;
      next();
    } catch (dbErr) {
      console.log("DB error:", dbErr.message);
      res.locals.user = null;
      next();
    }
  });
};




module.exports={requireAuth, checkUser};