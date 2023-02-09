import authController from "../controllers/auth.controller.js";

const authRoutes = (app) => {

  app.use( (req, res, next) => {
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, Content-Type, Accept"
    );
    next();
  })
 
  app.post('/api/auth/signin', authController.signIn);
}

export default authRoutes;