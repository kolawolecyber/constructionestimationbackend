const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const PasswordReset = require("../models/PasswordReset"); 
const router = require('../routes/auth');
const {Resend} = require('resend');
const passport = require('../config/passport');
const nodemailer = require("nodemailer");


const handleErrors=(err)=>{
  console.log(err.message, err.code)
    let errors = {email:'', password:''};
if (err.code===11000){
    errors.email= 'Email already Resgistered';
    return errors;
}
    if (err.message.includes('User validation failed')){
Object.values(err.errors).forEach(({properties})=>{
    errors[properties.path] = properties.message;
})
    }
return errors;
}

const maxAge = 3*24*60*60;
const createToken= id =>{
    return jwt.sign({id}, 'your_jwt_secret', {expiresIn:maxAge})
}

// signup 
const signup = async (req, res)=>{
  const { name, profession, phone, email, password } = req.body;

 try {
    let user = await User.findOne({ email });
     user = new User({ name,profession, phone, email, password});
     await user.validate();
    const salt = await bcrypt.genSalt();
    user.password = await bcrypt.hash(password, salt);
    
    await user.save();
    
    const token = createToken(user._id);
    res.cookie('jwt', token, {httpOnly: true,
  sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  secure: process.env.NODE_ENV === 'production',
  path: '/',
  maxAge: maxAge * 1000})
    
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.log(JSON.stringify(err, null, 2));
    const errors = handleErrors(err);
    res.status(500).json({ errors});
  }
};


//Login
const login = async (req, res) => { 
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Email incorrect' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Password incorrect' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      path: '/',
      maxAge: 60 * 60 * 1000 // 1 hour
    });

    res.status(200).json({ message: 'Login successful'});
    
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
};





//authentication for cookie with frontend
const getMe= (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ authenticated: false });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ authenticated: true, user: decoded });
  } catch (err) {
    res.status(401).json({ authenticated: false });
  }
};


// logout
const logout= async(req,res)=>{
res.clearCookie('jwt', {
   httpOnly: true,
  sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  secure: process.env.NODE_ENV === 'production',
  path: '/'
  });
  res.status(200).json({ message: 'Successfully logged out' });
}

const getId = async(req,res)=>{
  const id=req.params.id;
  User.findById(id)
  .then(result =>{
    res.render();
  }).catch(err =>{
    console.log(err);
  });
}

//Password forgot

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ msg: "User not found" });

  const secret = process.env.JWT_SECRET + user.password;
  const token = jwt.sign({ id: user._id, email: user.email }, secret, { expiresIn: '1h' });
  const link = `${process.env.FRONTEND_URL}/pages/ResetPassword/${user._id}/${token}`;

  // Create transporter for Gmail
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "cyberkonstruct@gmail.com", // your Gmail
      pass: "plri gxlo sgvy myur", // use app password (not your real password)
    },
  });

  try {
    await transporter.sendMail({
      from: '"Cyber Construct" <cyberconstruct@gmail.com>',
      to: user.email,
      subject: "Reset Your Password",
      html: `<p>Click the link below to reset your password:</p>
             <a href="${link}">${link}</a>`,
    });

    console.log("Password reset email sent successfully.");
    return res.json({ message: "Password reset link sent" });
  } catch (err) {
    console.error("Email sending error:", err);
    return res.status(500).json({ error: "Failed to send reset email" });
  }
};



//Password reset
const resetPassword = async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  const user = await User.findById(id);
  if (!user) return res.status(404).json({ msg: "User not found" });

  const secret = process.env.JWT_SECRET + user.password;

  try {
    jwt.verify(token, secret);

    const isSame = await bcrypt.compare(password, user.password);
    if (isSame) {
      return res.status(400).json({
        error: 'New password cannot be the same as the old one.'
      });
    }

    const hashed = await bcrypt.hash(password, 10);
    user.password = hashed;
    await user.save();

    // Clear any existing session cookie (logout everywhere)
    res.clearCookie('jwt', {
      httpOnly: true,
      sameSite: 'Strict',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });

    res.json({ msg: 'Password reset successful' });

  } catch (e) {
    res.status(400).json({ msg: 'Invalid or expired token' });
  }
};


// google Auth
 
const googleVerification = (req, res) => {
  const token = jwt.sign(
    { userId: req.user._id },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  // Set secure HTTP-only cookie
  res.cookie('jwt', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // only secure in production
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    path: '/',
    maxAge: 60 * 60 * 1000 // 1 hour
  });

  // Redirect to frontend without sending token in URL
  res.redirect(`${process.env.FRONTEND_URL}/auth/authSuccess?token=${token}`);
};


module.exports = {
    signup,
    login,
    getId,
    logout,
    forgotPassword,
    resetPassword,
    googleVerification,
    getMe
   
}