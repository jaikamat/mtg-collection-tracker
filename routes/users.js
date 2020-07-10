const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

/* GET users listing. */
router.get('/', async function (req, res, next) {
  res.send('GET /users');
});

// Create a new user (sign up)
router.post('/signup', authController.signup);

// Login a user
router.post('/login', authController.login);

/* POST user listing - edit user */
router.post('/:id', function (req, res, next) {
  res.send(`POST /users/${JSON.stringify(req.params)}`);
});

module.exports = router;
