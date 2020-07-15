const { promisify } = require('util');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../database/models/user');
const createError = require('http-errors');
const sendEmail = require('../utils/email');
const { SSL_OP_NETSCAPE_CA_DN_BUG } = require('constants');

/**
 * Signs a JWT token and embeds the user ID
 * @param {String} userId - A user ID
 */
const signToken = userId => {
    const { JWT_SECRET, JWT_EXPIRES_IN } = process.env;
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

/**
 * Decodes a JWT to expose its data
 * @param {String} token - A raw JWT token
 */
const decodeToken = async token => {
    return await promisify(jwt.verify)(token, process.env.JWT_SECRET); // Promisify the sync verify() method
}

const signup = async (req, res, next) => {
    try {
        const { password, username, email, role, passwordChangedAt } = req.body;

        const newUser = await User.create({
            password,
            username,
            email,
            role,
            passwordChangedAt
        });

        res.status(201).json({
            status: 'success',
            token: signToken(newUser._id),
            data: {
                user: newUser
            }
        })
    } catch (err) {
        return next(err);
    }
}

/**
 * User login controller
 */
const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) return next(createError(400, 'Email and password must be supplied'));

        const foundUser = await User.findOne({ email: email }); // Check if user exists

        if (!foundUser || !await foundUser.correctPassword(password)) { // Second statement won't run if no user found
            return next(createError(401, 'Incorrect email or password'));
        }

        return res.status(200).json({
            status: "success",
            token: signToken(foundUser._id)
        });
    } catch (err) {
        return next(err)
    }
}

/**
 * Sends user a reset token and sends to provided email address
 */
const forgotPassword = async (req, res, next) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email: email });

        if (!user) {
            return next(createError(404, 'There is no user with that email address'));
        }

        const resetToken = user.createPasswordResetToken(); // Modifies the User instance without persisting

        const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/reset-password/${resetToken}`;

        const subject = `Your password reset request (will expire in ten minutes)`;

        const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to ${resetURL}.
            \nIf you didn't forget your password, please ignore this email.`;

        try {
            await user.save(); // Save the modified user object

            await sendEmail({
                email: user.email,
                subject,
                message
            });
        } catch (err) { // If email fails to send, we need to reset the altered fields on the user model
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save();

            return next(createError(500, 'The email failed to send'));
        }

        res.status(200).json({
            status: 'success',
            message: 'Password reset token sent through mail' // NEVER SEND THE RESET TOKEN AS A RESPONSE
        })
    } catch (err) {
        return next(createError(500, err.message));
    }
}

/**
 * Allows users to reset their password
 */
const resetPassword = async (req, res, next) => {
    try {
        const { token } = req.params;
        const { password } = req.body;
        const hashedToken = crypto // Have to hash the token first before using it to find users
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken, // Find user by hashed token
            passwordResetExpires: { $gt: Date.now() } // Ensure the password reset token is not expired (expiry should be later than now)
        });

        if (!user) return next(createError(400, 'Token is invalid or has expired'));

        user.password = password; // Hash will occur during presave hook
        user.passwordResetToken = undefined; // Reset
        user.passwordResetExpires = undefined; // Reset

        await user.save(); // Trigger presave hooks to hash new password

        // Log the user in (send a JWT to the client)
        res.status(201).json({
            status: 'success',
            token: signToken(user._id),
            data: { user }
        })
    } catch (err) {
        return next(createError(500, err))
    }
}

/**
 * Update password functionality for logged-in users
 */
const updatePassword = async (req, res, next) => {
    // 0. Decode the token and get the user ID

    const { jwtToken } = req.body;

    if (!jwtToken) return next(createError(400, 'No authentication token was provided'));

    const decoded = await decodeToken(jwtToken);
    // 1. Get the user from the User collection
    // 2. Ensure password is correct
    // 3. Reset password that was provided
    // 4. Save and prehook function will hash
    // 5. Log the user in
}

/**
 * Resource route auth middleware
 */
const protect = async (req, res, next) => {
    try {
        const { jwtToken } = req.body;

        if (!jwtToken) return next(createError(401, 'Unauthorized'));

        const decoded = await decodeToken(jwtToken);

        const currentUser = await User.findById(decoded.id); // Find the user from the token UserID

        if (!currentUser) return next(createError(401, 'The user belonging to this token no longer exists'));

        if (!currentUser.tokenIssuedAfterPasswordChange(decoded.iat)) {
            return next(createError(401, 'Token issued before password change'));
        }

        req.user = currentUser; // Expose the user on the req object for further middleware use
        return next(); // Grant access to protected route
    } catch (err) {
        if (err.name === 'TokenExpiredError') return next(createError(401, err));
        if (err.name === 'JsonWebTokenError') return next(createError(401, err));
        return next(createError(401, 'Not authorized'));
    }
}

/**
 * Middleware that validates password and confirm-password fields from form submissions
 */
const validatePasswordMatch = (req, res, next) => {
    const { password, passwordConfirm } = req.body;

    if (password !== passwordConfirm) {
        return next(createError(400, 'Password and confirmed password must match'));
    }

    return next();
}

/**
 * Scans the incoming request for a Bearer JWT token, and if one is preset, tacks it onto the req object
 */
const applyTokenToReq = (req, res, next) => {
    const { authorization } = req.headers;
    let token;

    if (authorization && authorization.startsWith('Bearer ')) {
        token = authorization.split(' ')[1]; // Isolate token from headers
    }

    req.body.jwtToken = token;
    return next();
}

/**
 * Middleware that permits a user of a designated role to access resources
 * Used in conjunction with protect() which exposes req.user
 * @param {String} role - the user role
 */
const restrictTo = (...roles) => {
    return (req, res, next) => {
        const { role } = req.user;

        if (!roles.includes(role)) {
            return next(createError(403, `User role of '${role}' not permitted access`));
        }

        return next();
    }
}

module.exports.signup = signup;
module.exports.login = login;
module.exports.protect = protect;
module.exports.restrictTo = restrictTo;
module.exports.forgotPassword = forgotPassword;
module.exports.resetPassword = resetPassword;
module.exports.validatePasswordMatch = validatePasswordMatch;
module.exports.updatePassword = updatePassword;
module.exports.applyTokenToReq = applyTokenToReq;