const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sendVerificationEmail } = require('../utils/emailService');

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    const user = new User({ email, password: hashedPassword, verificationToken });
    await user.save();
    await sendVerificationEmail(email, verificationToken);

    res.status(201).send('User registered. Please verify your email.');
});

// Login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !user.isVerified) return res.status(400).send('Invalid credentials or email not verified.');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials.');

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Verify email
router.get('/verify/:token', async (req, res) => {
    try {
        const decoded = jwt.verify(req.params.token, process.env.JWT_SECRET);
        const user = await User.findOneAndUpdate({ email: decoded.email }, { isVerified: true, verificationToken: null });
        if (!user) return res.status(400).send('Invalid token.');
        res.send('Email verified successfully.');
    } catch (err) {
        res.status(400).send('Invalid token.');
    }
});

// Request password reset
router.post('/reset-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('User not found.');

    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetLink = `${process.env.BASE_URL}/reset-password/${resetToken}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Password Reset Request',
        html: `
            <p>You requested a password reset. Click the link below to reset your password:</p>
            <a href="${resetLink}">${resetLink}</a>
        `,
    };

    try {
        await transporter.sendMail(mailOptions);
        res.send('Password reset link sent.');
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).send('Error sending password reset email.');
    }
});

// Reset password
router.post('/reset-password/:token', async (req, res) => {
    const { password } = req.body;
    let userId;

    try {
        const decoded = jwt.verify(req.params.token, process.env.JWT_SECRET);
        userId = decoded.id;
    } catch (err) {
        return res.status(400).send('Invalid token.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(userId, { password: hashedPassword });
    res.send('Password updated successfully.');
});

module.exports = router;
