const db = require('../config/db');

// Create a 'users' table if it doesn't exist
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            isVerified BOOLEAN DEFAULT 0,
            verificationToken TEXT
        )
    `, (err) => {
        if (err) {
            console.error("Error creating users table:", err.message);
        } else {
            console.log("Users table created or already exists.");
        }
    });
});

// Function to create a new user
const createUser = (email, password, verificationToken, callback) => {
    const query = `INSERT INTO users (email, password, verificationToken) VALUES (?, ?, ?)`;
    db.run(query, [email, password, verificationToken], function(err) {
        if (err) {
            return callback(err);
        }
        callback(null, { id: this.lastID, email, password, verificationToken });
    });
};

// Function to find a user by email
const findUserByEmail = (email, callback) => {
    const query = `SELECT * FROM users WHERE email = ?`;
    db.get(query, [email], (err, row) => {
        if (err) {
            return callback(err);
        }
        callback(null, row);
    });
};

// Function to update user verification status
const verifyUser = (email, callback) => {
    const query = `UPDATE users SET isVerified = 1, verificationToken = NULL WHERE email = ?`;
    db.run(query, [email], (err) => {
        if (err) {
            return callback(err);
        }
        callback(null);
    });
};

module.exports = {
    createUser,
    findUserByEmail,
    verifyUser
};
