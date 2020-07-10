var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function (req, res, next) {
  return res.json({
    message: 'This is the home page'
  })
});

/* GET some protected route */
router.get('/protected', (req, res, next) => {
  return res.json({
    message: 'This is a protected route!'
  })
})

module.exports = router;
