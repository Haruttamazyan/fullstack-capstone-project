const express = require('express');
const app = express();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');  

const logger = pino();

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try{
        const db = await connectToDatabase();
        const collection = db.collection("users");
        const {email, firstName, lastName, password} = req.body;

        const existingEmail = await collection.findOne({ email });
        if(!!existingEmail){
            return res.status(404).send('User alerady exist');
        }
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(password, salt);

        const newUser = await collection.insertOne({
            email,
            firstName,
            lastName,
            password: hash,
            createdAt: new Date(),
        });

        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        const authtoken = jwt.sign(payload, JWT_SECRET);

        logger.info('User registered successfully');
        res.status(200).json({authtoken,email});
        
    } catch(e) {
        return res.status(500).send('Internal server error');
    }
});

module.exports = router;
