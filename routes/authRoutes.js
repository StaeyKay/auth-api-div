import { Router } from "express";
import { checkLink, forgotPassword, loadUser, login, logout, refreshToken, resetPassword, signup } from "../controllers/authController.js";
import { routeProtect } from "../middlewares/routeProtector.js";

const router = Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);
router.post('/forgotPassword', forgotPassword);
router.patch('/resetPassword/:resetPasswordToken', resetPassword);
router.get('/loadUser', loadUser);
router.get('/checkLink/:resetPasswordToken', checkLink);
router.get('/refreshToken', refreshToken);

export default router;