const express = require('express');
const router = express.Router();
const indexRouter = require('./index');
const usersRouter = require('./users');

router.use('/', indexRouter);
router.use('/users', usersRouter);

module.exports = router;