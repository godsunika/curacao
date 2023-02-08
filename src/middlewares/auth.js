import jwt from 'jsonwebtoken';

function Auth(req, res, next) {
  // const token = req.header("x-auth-token");
  const token = req.header('x-access-token');
  // const token = req.body.token || req.query.token || req.headers["x-access-token"];

  if (!token) return res.status(401).send('Access denied. Not authorized...');

  try {
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const decoded      = jwt.verify(token, jwtSecretKey);
    req.user           = decoded;
    next();
  } catch (err) {
    // console.log(er);
    res.status(401).send(err.name);
  }
}

export default Auth;
