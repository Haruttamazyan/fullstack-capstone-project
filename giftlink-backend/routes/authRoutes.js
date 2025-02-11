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
  try {
    const db = await connectToDatabase();
    const collection = db.collection('users');
    const { email, firstName, lastName, password } = req.body;

    const existingEmail = await collection.findOne({ email });
    if (!!existingEmail) {
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
    res.status(200).json({ authtoken, email });
  } catch (e) {
    return res.status(500).send('Internal server error');
  }
});

router.post('/login', async (req, res) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection('users');
    const { email, password } = req.body;

    const user = await collection.findOne({ email });
    if (!!user) {
      let result = await bcryptjs.compare(password, user.password);
      if (!result) {
        logger.error('Passwords do not match');
        return res.status(404).json({ error: 'Wrong pasword' });
      }

      let payload = {
        user: {
          id: user._id.toString(),
        },
      };
      const authtoken = jwt.sign(payload, JWT_SECRET);
      logger.info('User logged in successfully');
      return res
        .status(200)
        .json({ authtoken, userName: user.firstName, email });
    } else {
      logger.error('User not found');
      return res.status(404).json({ error: 'User not found' });
    }
  } catch (e) {
    console.log(e.message);
    return res.status(500).send('Internal server error');
  }
});

router.put('/update', async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error('Validation errors in update request', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const email = req.headers.email;
    if (!email) {
      logger.error('Email not found in the request headers');
      return res
        .status(400)
        .json({ error: 'Email not found in the request headers' });
    }
    const db = await connectToDatabase();
    const collection = db.collection('users');
    const existingUser = await collection.findOne({ email });
    if (!existingUser) {
      logger.error('User not found');
      return res.status(404).json({ error: 'User not found' });
    }
    existingUser.firstName = req.body.name;
    existingUser.updatedAt = new Date();
    const updatedUser = await collection.findOneAndUpdate(
      { email },
      { $set: existingUser },
      { returnDocument: 'after' }
    );
    const payload = {
      user: {
        id: updatedUser._id.toString(),
      },
    };
    const authtoken = jwt.sign(payload, JWT_SECRET);
    logger.info('User updated successfully');
    return res
      .status(200)
      .json({ authtoken, userName: existingUser.firstName, email });
  } catch (error) {
    logger.error(error);
    return res.status(500).send('Internal Server Error');
  }
});

module.exports = router;
