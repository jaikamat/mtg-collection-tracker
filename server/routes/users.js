const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const userController = require('../controllers/userController');

router
  .route('/')
  .get(
    authController.protect,
    authController.restrictTo('admin'),
    userController.getAllUsers
  )

router
  .route('/signup')
  .post(authController.validatePasswordMatch, authController.signup) // Create a new user (sign up)

router
  .route('/login')
  .post(authController.validatePasswordMatch, authController.login) // Login a user

router
  .route('/forgot-password')
  .post(authController.forgotPassword)

router
  .route('/reset-password/:token')
  .patch(authController.validatePasswordMatch, authController.resetPassword)

router
  .route('/update-password')
  .patch(
    authController.protect,
    authController.validatePasswordMatch,
    authController.updatePassword
  )

router
  .route('/:id')
  .get(
    authController.protect,
    userController.getOneUser
  )
  .patch(
    authController.protect,
    userController.userUpdate
  )
  .delete(
    authController.protect,
    userController.deleteUser
  )

module.exports = router;
