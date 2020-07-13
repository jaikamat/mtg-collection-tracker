const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../database/models/user');
const createError = require('http-errors');

const signToken = userId => {
    const { JWT_SECRET, JWT_EXPIRES_IN } = process.env;
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

const signup = async (req, res, next) => {
    try {
        const { password, passwordConfirm, username, email, passwordChangedAt } = req.body;

        // Check the password and confirmed passwords here, if no match, bad request
        if (passwordConfirm !== password) return next(createError(400, 'Passwords do not match'));

        const newUser = await User.create({
            password,
            username,
            email,
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
        next(err);
    }
}

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
        next(err)
    }
}

/**
 * Auth middleware
 */
const protect = async (req, res, next) => {
    try {
        const { authorization } = req.headers;
        let token;

        if (authorization && authorization.startsWith('Bearer ')) {
            token = authorization.split(' ')[1]; // Isolate token from headers
        }

        if (!token) return next(createError(401, 'Unauthorized'));

        const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET); // Promisify the sync verify() method

        const foundUser = await User.findById(decoded.id); // Find the user from the token UserID

        if (!foundUser) return next(createError(401, 'The user belonging to this token no longer exists'));

        if (!foundUser.tokenIssuedAfterPasswordChange(decoded.iat)) {
            return next(createError(401, 'Token issued before password change'));
        }

        req.user = foundUser;

        return next(); // Grant access to protected route
    } catch (err) {
        if (err.name === 'TokenExpiredError') return next(createError(401, err));
        if (err.name === 'JsonWebTokenError') return next(createError(401, err));
        return next(createError(401, 'Not authorized'));
    }
}

module.exports.signup = signup;
module.exports.login = login;
module.exports.protect = protect;