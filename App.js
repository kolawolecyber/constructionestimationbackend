require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const passport = require('passport');
require('./config/passport');
const session = require('express-session'); 
const cookieParser = require("cookie-parser");

const app = express();
const allowedOrigin = process.env.FRONTEND_URL;
app.use(cors({
  origin: allowedOrigin, // match your frontend origin
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

mongoose.connect(process.env.dbURI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.log(err, 'not connected'));

app.use(session({
  secret: process.env.SESSION_SECRET,  // e.g. a long, random string
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,            // set true in production under HTTPS
    sameSite: 'lax'
  }
}));
  app.use(passport.initialize());
app.use(passport.session());

app.use('/api/auth', authRoutes);
const PORT = process.env.PORT || 5000

app.listen(PORT, () => console.log('Server running on port 5000'));
