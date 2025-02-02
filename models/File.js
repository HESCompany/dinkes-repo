const mongoose = require('mongoose');

const FileSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    file: { type: String, required: true },
    tags: { type: [String] },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    uploadedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('File', FileSchema);
