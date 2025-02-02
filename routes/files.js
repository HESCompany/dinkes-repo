const express = require('express');
const router = express.Router();
const multer = require('multer');
const File = require('../models/File');
const { ensureAuthenticated } = require('../config/auth');

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, './public/uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

router.get('/upload', ensureAuthenticated, (req, res) => res.render('files/upload'));

router.post('/upload', ensureAuthenticated, upload.single('file'), (req, res) => {
    const { title, description, tags } = req.body;
    const newFile = new File({
        title,
        description,
        file: req.file.filename,
        tags: tags.split(','),
        uploadedBy: req.user.id,
    });
    newFile.save()
        .then(() => res.redirect('/dashboard'))
        .catch(err => console.log(err));
});

module.exports = router;
