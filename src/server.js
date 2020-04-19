import express from 'express';
import { urlencoded, json } from 'body-parser';
import cors from 'cors';
require('dotenv').config({ path: '.env' });

const server = express();

// Env Variables
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

// Database Connection
require('./config/connection');

// Parser From Req.body
server.use(urlencoded({ extended: true }));
server.use(json());

// Enable the CORS
server.use(function(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header(
        'Access-Control-Allow-Methods',
        'GET, PUT, POST, DELETE, OPTIONS'
    );
    res.header(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept'
    );
    next();
});
server.use(cors());

//Routes
import usersRouter from './routes/User';

// Server Route
server.get('/', function(req, res) {
    res.json({ message: 'Welcome to RESTFul API' });
});

server.use('/api/users', usersRouter);

// Server Start
server.listen(PORT, () => {
    console.log(`API Running at http://${HOST}:${PORT}/api`);
});
