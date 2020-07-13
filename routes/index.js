const express = require('express');
const router = express.Router();
const indexController = require('../controllers/indexController');
const authController = require('../controllers/authController');

router
  .route('/')
  .get(indexController.homepage)

router
  .route('/protected')
  .get(authController.protect, indexController.protected)
  .delete(
    authController.protect,
    authController.restrictTo('admin'),
    indexController.protected
  )

module.exports = router;
