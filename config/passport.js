const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passport = require('passport');
const User = require('../models/User');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/api/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    const result = await User.findOrCreate(
      { googleId: profile.id },
      { googleId: profile.id, email: profile.emails[0].value }
    );
    const user = result.doc || result; // plugin returns { doc, created }
    done(null, user);
  }
));
