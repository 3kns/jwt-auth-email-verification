const mongoose = require('mongoose');

const connectDB =  mongoose.createConnection('mongodb://127.0.0.1:27017/Auth').on('open', ()=>{
    console.log("Database connected successfully");
}).on('error', ()=>{
    console.log("Error connecting to database");
});

module.exports = connectDB;
