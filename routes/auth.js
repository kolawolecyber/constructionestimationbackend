const express = require('express');
const router = express.Router();
const authcontroller = require('../controller/authcontroller');
const { requireAuth,checkUser} = require('../middleware/authMiddleware');
const passport = require('passport');

// Register
router.post('/register',authcontroller.signup );

// Login
router.post('/login', authcontroller.login);

//GetId
router.get('/get',  requireAuth,
  checkUser, authcontroller.getId);

  //Logout
router.post('/logout', authcontroller.logout);

//forgot password
router.post('/forgot_password', authcontroller.forgotPassword);

//reset password
router.post('/reset_password/:id/:token', authcontroller.resetPassword);

//for protected route
router.get('/api/auth/me', authcontroller.getMe);
//google Auth
router.get('/google',  passport.authenticate('google', { scope: ['profile', 'email'] }));

// google call vack verify
router.get('/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/login',
    session: false
  }), authcontroller.googleVerification);

module.exports = router;
