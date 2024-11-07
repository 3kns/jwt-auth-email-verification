const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

const sendVerificationEmail = (email, token) => {
    const url = `${process.env.BASE_URL}/auth/verify/${token}`;
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Email Verification',
        text: `Please verify your email by clicking on the following link: ${url}`,
    };

    return transporter.sendMail(mailOptions);
};

module.exports = { sendVerificationEmail };
