import jwt  from "jsonwebtoken";
import User from "../models/user.js";

export const routeProtect = async (req, res, next) => {
    try {

        // attempt to get token from request
        const token = req.cookies.jwt;

        // throw error if token doesn't exist
        if(!token) {
            const error = new Error('You are not authenticated');
            error.statusCode = 401;
            return next(error);
        }

        // verify the token
        const verifyToken = jwt.verify(token, process.env.JWT_SECRET);
        if(!verifyToken) {
            const error = new Error('Invalid token');
            error.statusCode = 401;
            return next(error);
        }

        // console.log(verifyToken);

        const user = await User.findById(verifyToken.id).select('-password');
        req.loggedInUser = user;

        next();
        
    } catch (error) {
        next(error);
    }
}