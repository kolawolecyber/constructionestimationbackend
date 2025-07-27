const mongoose = require('mongoose');
const { isEmail } = require('validator');
const findOrCreate = require('mongoose-findorcreate');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: function () { return !this.googleId; },
    message: 'Please enter your full name'
  },
  profession: {
    type: String,
    required: function () { return !this.googleId; },
  },
  phone: {
    type: String,
    required: function () { return !this.googleId; },
    message: 'Phone number is required'
  },
  email: {
    type: String,
    required: [true, 'Please enter an email'],
    unique: true,
    lowercase: true,
    validate: [isEmail, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: function () { return !this.googleId; },
    minlength: [5, 'Minimum password length is 5 characters']
  },
  googleId: {
    type: String
  }
});

// Add plugin for findOrCreate if using Passport strategy
UserSchema.plugin(findOrCreate);

module.exports = mongoose.model('User', UserSchema);
