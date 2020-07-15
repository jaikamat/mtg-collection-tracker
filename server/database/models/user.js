const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const UserSchema = mongoose.Schema({
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    username: {
        type: String,
        unique: true,
        required: true
    },
    email: {
        type: String,
        unique: true,
        required: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    role: {
        type: String,
        enum: ['user', 'member', 'admin', 'owner'],
        default: 'user'
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date
})

/**
 * Presave hook that hashes provided passwords prior to persisting
 */
UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next(); // If non-password field is modified, we don't want to re-hash the password

    this.password = await bcrypt.hash(this.password, 12);

    next();
})

UserSchema.pre('save', function (next) {
    if (!this.isModified('password') || this.isNew) return next(); // If password not modified OR if new user created (the password was not changed), exit

    this.passwordChangedAt = Date.now() - 1000; // Subtract 1s to account for possible async token generation in the past
    return next();
})

/**
 * Instance method that compares a hash against its assumed plaintext equivalent
 */
UserSchema.methods.correctPassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
}

/**
 * Instance method that determines if a user changed their password after a token was issued
 */
UserSchema.methods.tokenIssuedAfterPasswordChange = function (JWTtimestamp) {
    if (!this.passwordChangedAt) { // If user instance does not have passwordChangedAt field, no need to check token against date
        return true;
    }

    const passwordChangeTime = parseInt(this.passwordChangedAt.getTime() / 1000, 10); // Need to get this in sec, getTime() yields ms

    return (JWTtimestamp - passwordChangeTime) > 0; // JWT should be issued after the password was changed
}

/**
 * Instance method that generates a user's reset token
 */
UserSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex'); // Never store this in the database

    this.passwordResetToken = crypto // Have to hash the token first before saving to db
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');

    this.passwordResetExpires = Date.now() + 600000; // Adding 10m * 60s * 1000ms to get 10 mins in ms

    console.log({ resetToken }, this.passwordResetToken);

    return resetToken; // Send the unencrypted reset token to the user
}

const User = mongoose.model('User', UserSchema);
module.exports = User;