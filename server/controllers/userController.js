const User = require('../database/models/user');
const createError = require('http-errors');

/**
 * Retrieves all active users in the system
 */
const getAllUsers = async (req, res, next) => {
    try {
        const users = await User.find({});
        res.status(200).json({ users });
    } catch (err) {
        return next(createError(500, err))
    }
}

/**
 * Soft-deletes the specified user by setting 'active' to false
 */
const deleteUser = async (req, res, next) => {
    try {
        const { role } = req.user;
        const { id } = req.params;

        if (role !== 'admin' && id !== req.user.id) { // If you're not an admin, your id should match the resource id
            return next(createError(400, 'Can only delete yourself'));
        }

        await User.findByIdAndUpdate(id, { active: false });

        res.status(200).json({
            status: 'success',
            data: null
        });
    } catch (err) {
        return next(createError(500, err));
    }
}

module.exports.getAllUsers = getAllUsers;
module.exports.deleteUser = deleteUser;