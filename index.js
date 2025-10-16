const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const jwkToPem = require('jwk-to-pem');
require('dotenv').config();

const crypto = require('crypto');

const SUPABASE_JWKS_URL = `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`;
let jwksCache = null;
async function getSupabaseJwks() {
    if (!jwksCache) {
        const { data } = await axios.get(SUPABASE_JWKS_URL, {
            headers: { apikey: process.env.SUPABASE_ANON },
        });
        jwksCache = data.keys;
    }
    return jwksCache;
}

async function verifySupabaseToken(token) {
    if (!token) throw new Error('Missing token');

    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');

    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
    const jwks = await getSupabaseJwks();
    const jwk = jwks.find(k => k.kid === header.kid);

    if (!jwk) throw new Error('Matching JWK not found');

    const pem = jwkToPem(jwk);
    const decoded = jwt.verify(token, pem, { algorithms: ['ES256'] });

    return decoded;
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const allowedOrigins = [
    "https://mindflow-lake.vercel.app",
    "http://localhost:8080"
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) {
            return callback(null, true); // allow non-browser requests
        }
        if (allowedOrigins.some(o => origin.startsWith(o))) {
            return callback(null, true);
        }
        return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
}));

const algorithm = 'aes-256-cbc';
const secretKey = crypto.createHash('sha256').update(process.env.JWT_SECRET).digest(); // Reuse JWT secret or set ENCRYPTION_SECRET in .env

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    const [ivStr, encryptedStr] = text.split(':');
    if (!ivStr || !encryptedStr) throw new Error('Invalid encrypted text');
    const iv = Buffer.from(ivStr, 'hex');
    const encrypted = Buffer.from(encryptedStr, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString();
}



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

const jsonSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    docId: { type: String, required: true },
    json: { type: String, required: true }, // Stored as stringified JSON
    createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Document = mongoose.model('Document', documentSchema);
const Json = mongoose.model('Json', jsonSchema, 'jsons');

// Middleware to verify JWT
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    try {
        let decoded;

        // 🔍 1. Detect if it's a Supabase token
        if (token.includes('supabase.co')) {
            // just in case someone sent a wrong format
            return res.status(400).json({ error: 'Invalid Supabase token format' });
        }

        const parts = token.split('.');
        const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));

        // Supabase tokens typically have `iss` = your Supabase URL
        if (header.kid || header.iss?.includes('supabase.co')) {
            decoded = await verifySupabaseToken(token);

            const email =
                decoded.email ||
                decoded.user_metadata?.email ||
                decoded.user_metadata?.preferred_username;

            const user = await User.findOne({ email });
            if (!user) return res.status(401).json({ error: 'User not found' });

            req.user = { id: user.id, email: user.email };
        } else {
            // 🔑 Otherwise, use your local JWT verification
            decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = { id: decoded.id, email: decoded.email };
        }

        next();
    } catch (err) {
        console.error('Auth middleware error:', err);
        res.status(403).json({ error: 'Invalid or expired token' });
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

app.post('/api/auth/supabase', async (req, res) => {
    try {
        const { token } = req.body;
        const decoded = await verifySupabaseToken(token);

        const email =
            decoded.email ||
            decoded.user_metadata?.email ||
            decoded.user_metadata?.preferred_username;

        if (!email) {
            return res.status(400).json({ error: 'No email found in Supabase token' });
        }

        let user = await User.findOne({ email });

        if (!user) {
            user = new User({
                id: decoded.sub, // Supabase UID
                email,
                name:
                    decoded.user_metadata?.full_name ||
                    decoded.user_metadata?.name ||
                    email.split('@')[0],
                isGoogleAuth: true,
            });
            await user.save();
        } else if (!user.isGoogleAuth) {
            // Convert existing email-password user to Supabase Google
            user.isGoogleAuth = true;
            if (!user.name)
                user.name =
                    decoded.user_metadata?.full_name ||
                    decoded.user_metadata?.name ||
                    email.split('@')[0];
            await user.save();
        }

        res.json({
            user: { id: user.id, email: user.email, name: user.name },
            token,
        });
    } catch (error) {
        console.error('Supabase auth error:', error);
        res.status(500).json({ error: 'Supabase authentication failed' });
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

app.post('/api/share', authenticateToken, async (req, res) => {
    try {
        const { docId, json } = req.body;
        if (!docId || !json) {
            return res.status(400).json({ error: 'Missing required fields: docId or json' });
        }
        // Verify user owns the document
        const doc = await Document.findOne({ id: docId, userId: req.user.id });
        if (!doc) {
            return res.status(404).json({ error: 'Document not found or not authorized' });
        }
        const snapshotId = uuidv4();
        const snapshot = new Json({
            id: snapshotId,
            docId,
            json, // Stringified JSON
        });
        await snapshot.save();
        const encryptedId = encrypt(snapshotId);
        const baseUrl = process.env.FRONTEND_URL || 'http://localhost:8080';
        const shareLink = `${baseUrl}?share=${encryptedId}`; // Use query param
        res.json({ shareLink });
    } catch (error) {
        console.error('Error creating share link:', error);
        res.status(500).json({ error: 'Failed to create share link' });
    }
});

app.get('/api/share/:encryptedId', async (req, res) => { // Unauthenticated
    try {
        const snapshotId = decrypt(req.params.encryptedId);
        const snapshot = await Json.findOne({ id: snapshotId });
        if (!snapshot) {
            return res.status(404).json({ error: 'Shared JSON not found' });
        }
        res.json({ json: snapshot.json });
    } catch (error) {
        console.error('Error fetching shared JSON:', error);
        res.status(400).json({ error: 'Invalid share link' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));