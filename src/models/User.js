import mongoose from 'mongoose';

// TODO: Add User Schema
const schema = new mongoose.Schema({
    username: { type: String, required: true, max: 10 },
    email: { type: String, required: true },
    password: { type: String, required: true },
    token: { type: String },
    expTime: { type: Number },
});

const User = new mongoose.model('User', schema);

export default User;
