import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import winston from 'winston';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import signIn from './src/routes/signIn.js';
import signUp from './src/routes/signUp.js';

dotenv.config();

winston.exceptions.handle(
  new winston.transports.Console({ colorize: true, prettyprint: true }),
  new winston.transports.File({ filename: 'uncaughtExceptions.log' }),
);

process.on('unhandledRejection', (error) => {
  throw error;
});

winston.add(new winston.transports.File({ filename: 'logfile.log' }));

const app         = express();

const corsOptions = {
  origin: ['http://localhost:8080', 'http://localhost:3000', 'http://localhost:3001'],
  // origin: '*',
  // methods: '*',
  credentials: true,            // access-control-allow-credentials:true
  optionSuccessStatus: 200,
  // exposedHeaders: ["set-cookie"],
};

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors(corsOptions));
app.use(cookieParser());

app.use('/api/signin', signIn);
app.use('/api/signup', signUp);

const port = process.env.PORT || 3000;

app.listen(port, () => console.log('Example app listening on port 3000!'));
