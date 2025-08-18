require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');
const passport = require('passport');
require('./config/passport');

const app = express();

// CORS config for cookies
const allowedOrigin = process.env.FRONTEND_URL;
app.use(cors({
  origin: allowedOrigin || "http://localhost:3000",
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

// DB connect
mongoose.connect(process.env.dbURI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.log(err, 'not connected'));

// Routes
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
