const express = require('express');
const router = express.Router();
const passport = require('passport');
const User = require('../models/User');

router.get('/login', (req, res) => res.render('users/login'));
router.get('/register', (req, res) => res.render('users/register'));

router.post('/register', (req, res) => {
    const { name, email, password, role } = req.body;
    const newUser = new User({ name, email, password, role });
    newUser.save()
        .then(user => res.redirect('/users/login'))
        .catch(err => console.log(err));
});

router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true,
    })(req, res, next);
});

router.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/users/login');
});

module.exports = router;
