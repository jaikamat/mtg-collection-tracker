const jwt = require('jsonwebtoken');
const User = require('../database/models/user');
const createError = require('http-errors');

const signup = async (req, res, next) => {
    try {
        const { JWT_SECRET, JWT_EXPIRES_IN } = process.env;
        const { password, passwordConfirm, username, email } = req.body;

        // Check the password and confirmed passwords here, if no match, bad request
        if (passwordConfirm !== password) return next(createError(400, 'Passwords do not match'));

        const newUser = await User.create({
            password,
            username,
            email
        });

        const token = jwt.sign({ id: newUser._id }, JWT_SECRET, {
            expiresIn: JWT_EXPIRES_IN
        });

        res.status(201).json({
            status: 'success',
            token,
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
        const { JWT_SECRET, JWT_EXPIRES_IN } = process.env;
        const { email, password } = req.body;

        if (!email || !password) return next(createError(400, 'Email and password must be supplied'));

        const foundUser = await User.findOne({ email: email }); // Check if user exists

        if (!foundUser || !await foundUser.correctPassword(password)) { // Second statement won't run if no user found
            return next(createError(401, 'Incorrect email or password'));
        }

        const token = jwt.sign({ id: foundUser._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        return res.status(200).json({
            status: "success",
            token
        });
    } catch (err) {
        next(err)
    }
}

module.exports.signup = signup;
module.exports.login = login;