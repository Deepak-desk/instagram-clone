const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
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
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// MongoDB Connection (FIXED - removed deprecated options)
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

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    fullName: { type: String, default: '' },
    profilePic: { type: String, default: 'https://i.imgur.com/V4RclNb.png' },
    bio: { type: String, default: '' },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    image: { type: String, required: true },
    caption: { type: String, default: '' },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        text: String,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});

const Post = mongoose.model('Post', postSchema);

// Auth Middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Routes
// Login Page
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/home');
    }
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/home');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Signup Page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Login POST
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user by username or email
        const user = await User.findOne({
            $or: [
                { username: username.toLowerCase() }, 
                { email: username.toLowerCase() }
            ]
        });

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Set session
        req.session.userId = user._id;
        req.session.username = user.username;

        console.log(`✅ User logged in: ${user.username}`);
        res.json({ success: true, message: 'Login successful', redirect: '/home' });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Signup POST
app.post('/api/signup', async (req, res) => {
    try {
        const { email, fullName, username, password } = req.body;

        // Validate input
        if (!email || !username || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Check if user exists
        const existingUser = await User.findOne({
            $or: [
                { username: username.toLowerCase() }, 
                { email: email.toLowerCase() }
            ]
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user
        const newUser = new User({
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password: hashedPassword,
            fullName
        });

        await newUser.save();

        // Set session
        req.session.userId = newUser._id;
        req.session.username = newUser.username;

        console.log(`✅ New user registered: ${username}`);
        res.json({ success: true, message: 'Account created', redirect: '/home' });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Home Page (Protected)
app.get('/home', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            req.session.destroy();
            return res.redirect('/login');
        }
        
        const posts = await Post.find()
            .populate('user', 'username profilePic')
            .populate('comments.user', 'username')
            .sort({ createdAt: -1 })
            .limit(20);

        res.render('home', { user, posts });
    } catch (error) {
        console.error('Home page error:', error);
        res.status(500).send('Server error');
    }
});

// Get all users (for testing)
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json({ count: users.length, users });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Like a post
app.post('/api/posts/:id/like', isAuthenticated, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        const userId = req.session.userId;

        if (post.likes.includes(userId)) {
            post.likes = post.likes.filter(id => id.toString() !== userId.toString());
        } else {
            post.likes.push(userId);
        }

        await post.save();
        res.json({ likes: post.likes.length });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n🚀 Server running on http://localhost:${PORT}`);
    console.log(`📱 Login page: http://localhost:${PORT}/login`);
    console.log(`📝 Signup page: http://localhost:${PORT}/signup\n`);
});