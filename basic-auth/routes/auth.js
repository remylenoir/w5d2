const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/user');
const router = express.Router();
const zxcvbn = require('zxcvbn');

router.get('/register', (req, res, next) => {
  res.render('register');
});

router.post('/register', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const salt = bcrypt.genSaltSync();
  const hashPassword = bcrypt.hashSync(password, salt);

  if (username === '' || password === '') {
    res.render('register', {
      errorMessage: 'You need a username and a password to register'
    });
    return;
  }
  const passwordStrength = zxcvbn(password);
  if (password.length < 6) {
    res.render('register', {
      errorMessage: 'Your password needs 6 or more characters'
    });
    return;
  }
  if (passwordStrength.score === 0) {
    res.render('register', {
      errorMessage: passwordStrength.feedback.warning
    });
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render('register', {
          errorMessage: 'There is already a registered user with this username'
        });
        return;
      }
      User.create({ username, password: hashPassword })
        .then(() => {
          res.redirect('/');
        })
        .catch(err => {
          console.error('Error while registering new user', err);
          next();
        });
    })
    .catch(err => {
      console.error('Error while looking for user', err);
    });
});

module.exports = router;
