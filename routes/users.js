const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

/* GET users listing. */
router.get('/', async function (req, res, next) {
  res.send('GET /users');
});

router
  .route('/signup')
  .post(authController.signup) // Create a new user (sign up)

router
  .route('/login')
  .post(authController.login) // Login a user

// /* POST user listing - edit user */
// router.post('/:id', function (req, res, next) {
//   res.send(`POST /users/${JSON.stringify(req.params)}`);
// });

module.exports = router;
