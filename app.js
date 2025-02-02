const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Replace with your MySQL username
    password: '', // Replace with your MySQL password
    database: 'dinkes_repo',
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected');
});

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, './public/uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// Routes
app.get('/', (req, res) => {
    res.send('Welcome to Dinkes Repository');
});

// Upload file
app.post('/upload', upload.single('file'), (req, res) => {
    const { title, description, tags, uploaded_by } = req.body;
    const file_path = req.file.filename;

    const sql = `
        INSERT INTO files (title, description, file_path, tags, uploaded_by)
        VALUES (?, ?, ?, ?, ?)
    `;
    db.query(sql, [title, description, file_path, tags, uploaded_by], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error uploading file');
        }
        res.status(200).send('File uploaded successfully');
    });
});

// Get all files
app.get('/files', (req, res) => {
    const sql = 'SELECT * FROM files';
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching files');
        }
        res.status(200).json(results);
    });
});

// Download file
app.get('/download/:id', (req, res) => {
    const fileId = req.params.id;
    const sql = 'SELECT file_path FROM files WHERE id = ?';
    db.query(sql, [fileId], (err, results) => {
        if (err || results.length === 0) {
            console.error(err);
            return res.status(404).send('File not found');
        }
        const filePath = path.join(__dirname, 'public', 'uploads', results[0].file_path);
        res.download(filePath);
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));