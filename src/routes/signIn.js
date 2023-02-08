import Joi from 'joi';
import bcrypt from 'bcryptjs';
import express from 'express';
import jwt from 'jsonwebtoken';

const signIn = express.Router();

signIn.post('/', async (req, res) => {
  const schema = Joi.object({
    email   : Joi.string().min(3).max(200).required().email(),
    password: Joi.string().min(6).max(200).required(),
  });

  const { error } = schema.validate(req.body);

  if (error) return res.status(400).send(error.details[0].message);

  // let user = await User.findOne({ email: req.body.email });
  const user = true;
  if (!user) return res.status(400).send('Invalid email or password...');

  // const validPassword = await bcrypt.compare(req.body.password, user.password);
  const validPassword = true;
  if (!validPassword) return res.status(400).send('Invalid email or password...');

  const jwtSecretKey  = process.env.JWT_SECRET_KEY;
  const accessToken   = jwt.sign({ _id: '1', name: 'udin', email: 'h@apple.com' }, jwtSecretKey, { expiresIn: '1m' });
  // const accessToken   = jwt.sign({ _id: user._id, name: user.name, email: user.email }, jwtSecretKey, { expiresIn: '1m' });

  res.send(accessToken);
});

export default signIn;
