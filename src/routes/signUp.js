import Joi from 'joi';
import bcrypt from 'bcryptjs';
import express from 'express';
import jwt from 'jsonwebtoken';

const signUp = express.Router();

signUp.post('/', async (req, res) => {
  const schema = Joi.object({
    name    : Joi.string().min(3).max(30).required(),
    email   : Joi.string().min(3).max(200).required().email(),
    password: Joi.string().min(6).max(200).required(),
  });

  const { error } = schema.validate(req.body);

  if (error) return res.status(400).send(error.details[0].message);

  // let user = await User.findOne({ email: req.body.email });
  let user = true;
  if (!user) return res.status(400).send('User already exists...');

  const { name, email, password:passw } = req.body;

  // user = new User({ name, email, password });
  user = {
    name: 'Hussein',
    email: 'hussein@gmail.com',
    password: passw,
  };

  const salt    = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(user.password, salt);

  // await user.save();

  const jwtSecretKey  = process.env.JWT_SECRET_KEY;
  // const accessToken   = jwt.sign({ _id: '1', name: 'udin', email: 'h@apple.com' }, jwtSecretKey, { expiresIn: '1m' });
  const accessToken   = jwt.sign({ _id: '1', name: user.name, email: user.email }, jwtSecretKey, { expiresIn: '1m' });

  res.send(accessToken);
});

export default signUp;
