const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');

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
    }
})

/**
 * Presave hook that hashes provided passwords prior to persisting
 */
UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next(); // If non-password field is modified, we don't want to re-hash the password

    this.password = await bcrypt.hash(this.password, 12);

    next();
})

/**
 * Instance method that compares a hash against its assumed plaintext equivalent
 */
UserSchema.methods.correctPassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
}

const User = mongoose.model('User', UserSchema);
module.exports = User;