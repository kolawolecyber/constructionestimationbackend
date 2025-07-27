const mongoose = require ('mongoose');
const Schema = mongoose.Schema;
const PasswordResetSchema = new Schema({
    userid: String,
    resetString: String,
    createdAt: Date,
    expiresAt:Date
});
const PasswordReset = mongoose.model("PasswordReset", PasswordResetSchema);
module.exports = PasswordReset;