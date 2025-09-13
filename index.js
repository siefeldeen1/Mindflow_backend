const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin
admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    })
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB')).catch((error) => {
    console.error('MongoDB connection error:', error);
});

// Schemas
const userSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    name: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    isGoogleAuth: { type: Boolean, default: false }
});

const documentSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    userId: { type: String, required: true },
    name: { type: String, required: true },
    state: { type: Object, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Document = mongoose.model('Document', documentSchema);

// Middleware to verify JWT
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        // Check if it's a Firebase token
        try {
            const decoded = await admin.auth().verifyIdToken(token);
            req.user = { id: decoded.uid, email: decoded.email };
            return next();
        } catch (error) {
            // If not Firebase, try JWT
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            next();
        }
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            id: uuidv4(),
            email,
            password: hashedPassword,
            name
        });

        await user.save();

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
            expiresIn: '3d'
        });

        res.json({
            user: { id: user.id, email: user.email, name: user.name },
            token
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.isGoogleAuth) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
            expiresIn: '3d'
        });

        res.json({
            user: { id: user.id, email: user.email, name: user.name },
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        const decoded = await admin.auth().verifyIdToken(token);

        let user = await User.findOne({ email: decoded.email });

        if (!user) {
            user = new User({
                id: decoded.uid,
                email: decoded.email,
                name: decoded.name || decoded.email.split('@')[0],
                isGoogleAuth: true
            });
            await user.save();
        }

        res.json({
            user: { id: user.id, email: user.email, name: user.name },
            token
        });
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(500).json({ error: 'Google authentication failed' });
    }
});

// Document Routes
app.get('/api/documents', authenticateToken, async (req, res) => {
    try {
        const documents = await Document.find({ userId: req.user.id });
        res.json(documents);
    } catch (error) {
        console.error('Error fetching documents:', error);
        res.status(500).json({ error: 'Failed to fetch documents' });
    }
});

app.get('/api/documents/:id', authenticateToken, async (req, res) => {
    try {
        const document = await Document.findOne({ id: req.params.id, userId: req.user.id });
        if (!document) {
            return res.status(404).json({ error: 'Document not found' });
        }
        res.json(document);
    } catch (error) {
        console.error('Error fetching document:', error);
        res.status(500).json({ error: 'Failed to fetch document' });
    }
});

app.post('/api/documents', authenticateToken, async (req, res) => {
    try {
        const { id, name, state } = req.body;
        if (!id || !name || !state) {
            return res.status(400).json({ error: 'Missing required fields: id, name, or state' });
        }
        // Check if document exists for another user
        const existingDoc = await Document.findOne({ id });
        if (existingDoc && existingDoc.userId !== req.user.id) {
            return res.status(400).json({ error: `Document ID ${id} already exists for another user` });
        }
        const document = await Document.findOneAndUpdate(
            { id, userId: req.user.id },
            { id, userId: req.user.id, name, state },
            { upsert: true, new: true }
        );
        res.json(document);
    } catch (error) {
        console.error('Error saving document:', error);
        if (error.code === 11000) {
            return res.status(400).json({ error: `Duplicate document ID ${req.body.id} for user ${req.user.id}` });
        }
        res.status(500).json({ error: `Failed to save document: ${error.message}` });
    }
});

app.put('/api/documents', authenticateToken, async (req, res) => {
    try {
        const { id, name, state } = req.body;
        if (!id || !name || !state) {
            return res.status(400).json({ error: 'Missing required fields: id, name, or state' });
        }
        const document = await Document.findOneAndUpdate(
            { id, userId: req.user.id },
            { name, state },
            { new: true }
        );
        if (!document) {
            return res.status(404).json({ error: 'Document not found for this user' });
        }
        res.json(document);
    } catch (error) {
        console.error('Error updating document:', error);
        res.status(500).json({ error: `Failed to update document: ${error.message}` });
    }
});

app.delete('/api/documents/:id', authenticateToken, async (req, res) => {


    try {
        const result = await Document.deleteOne({ id: req.params.id, userId: req.user.id });
        console.log(result);
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Document not found or not authorized' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting document:', error);
        res.status(500).json({ error: 'Failed to delete document' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));