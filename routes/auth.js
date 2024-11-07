const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createUser, findUserByEmail, verifyUser, updatePassword } = require('../models/User');
const { sendVerificationEmail } = require('../utils/emailService');
const nodemailer = require('nodemailer');

const router = express.Router();

// Register
router.post('/register', (req, res) => {
    const { email, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Error hashing password.');

        const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        createUser(email, hashedPassword, verificationToken, (err, user) => {
            if (err) return res.status(500).send('Error creating user.');
            sendVerificationEmail(email, verificationToken)
                .then(() => res.status(201).send('User registered. Please verify your email.'))
                .catch(() => res.status(500).send('Error sending verification email.'));
        });
    });
});

// Login
router.post('/login', (req, res) => {
    const { email, password } = req.body;
    findUserByEmail(email, (err, user) => {
        if (err || !user || !user.isVerified) return res.status(400).send('Invalid credentials or email not verified.');

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) return res.status(400).send('Invalid credentials.');
            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        });
    });
});

// Verify email
router.get('/verify/:token', (req, res) => {
    try {
        const decoded = jwt.verify(req.params.token, process.env.JWT_SECRET);
        verifyUser(decoded.email, (err) => {
            if (err) return res.status(400).send('Invalid token.');
            res.send('Email verified successfully.');
        });
    } catch (err) {
        res.status(400).send('Invalid token.');
    }
});

// Request password reset
router.post('/reset-password', async (req, res) => {
    const { email } = req.body;
    findUserByEmail(email, async (err, user) => {
        if (err || !user) return res.status(400).send('User not found.');

        const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
        const resetLink = `${process.env.BASE_URL}/reset-password/${resetToken}`;

        // Email content
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset Request',
            html: `
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <a href="${resetLink}">${resetLink}</a>
            `,
        };

        // Create a transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        try {
            await transporter.sendMail(mailOptions);
            res.send('Password reset link sent.');
        } catch (error) {
            console.error('Error sending email:', error);
            res.status(500).send('Error sending password reset email.');
        }
    });
});

// Reset password
router.post('/reset-password/:token', (req, res) => {
    const { password } = req.body;
    let userId;

    try {
        const decoded = jwt.verify(req.params.token, process.env.JWT_SECRET);
        userId = decoded.id;
    } catch (err) {
        return res.status(400).send('Invalid token.');
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Error hashing password.');
        updatePassword(userId, hashedPassword, (err) => {
            if (err) return res.status(500).send('Error updating password.');
            res.send('Password updated successfully.');
        });
    });
});

module.exports = router;
