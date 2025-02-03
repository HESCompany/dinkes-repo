const express = require('express');
const app = express();

// Set EJS sebagai view engine
app.set('view engine', 'ejs');

// Akses halaman utama
app.get('/', (req, res) => {
  res.render('index', { title: 'Home' });
});

// Jalankan server di port 3000
app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
