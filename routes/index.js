const express = require('express');
const router = express.Router();
const { ensureAuthenticated } = require('../config/auth');
const File = require('../models/File');

router.get('/dashboard', ensureAuthenticated, (req, res) => {
    File.find({})
        .populate('uploadedBy')
        .then(files => res.render('dashboard', { user: req.user, files }))
        .catch(err => console.log(err));
});

module.exports = router;
