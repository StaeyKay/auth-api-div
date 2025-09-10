import jwt from "jsonwebtoken";
import User from "../models/user.js";
import crypto from "crypto";
import { sendMail } from "../config/sendMail.js";

export const signup = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    const error = new Error("All fields are required");
    error.statusCode = 400;
    return next(error);
  }

  try {
    const user = await User.create(req.body);

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.cookie("jwt", token, {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true, // cookie should be set only through the http protocol coming from the backend
      secure: process.env.NODE_ENV === "production",
    });

    res.status(201).json({
      success: true,
      message: "Sign up successful",
      user,
    });
  } catch (error) {
    
    next(error);
  }
};

export const login = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    const error = new Error("Email and password are required");
    error.statusCode = 400;
    return next(error);
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      const error = new Error("Incorrect credentials");
      error.statusCode = 401;
      return next(error);
    }

    const isMatch = await user.comparePassword(password, user.password);

    if (!isMatch) {
      const error = new Error("Incorrect credentials");
      error.statusCode = 401;
      return next(error);
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "3m",
    });

    const refreshToken = jwt.sign({id: user._id}, process.env.JWT_REFRESH_SECRET, {
      expiresIn: '7d'
    })

    res.cookie("jwt", token, {
      maxAge: 3 * 60 * 1000, // 24 * 60 * 60 * 1000
      httpOnly: true, // cookie should be set only through the http protocol coming from the backend
      secure: process.env.NODE_ENV === "production",
    })
    .cookie('refreshJwt', refreshToken, {
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      httpOnly: true,
      secure: process.env.NODE_ENV === "production"
    })

    res.status(201).json({
      success: true,
      message: "Login successful",
      user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
    next(error);
  }
};

export const logout = async (req, res, next) => {
  try {
    res.clearCookie("jwt");
    res.clearCookie("refreshJwt");

    res.status(200).json({
      success: true,
      message: "user logged out",
    });
  } catch (error) {
    next(error);
  }
};

export const forgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    if (!email) {
      const error = new Error("Email is required.");
      error.statusCode = 400;
      return next(error);
    }

    const user = await User.findOne({ email });

    if (!user) {
      const error = new Error("The user with this email does not exist.");
      error.statusCode = 400;
      return next(error);
    }

    const resetToken = user.generatePasswordResetToken();

    await user.save({ validateBeforeSave: false });

    const resetUrl = `${req.protocol}://localhost:5173/resetPassword/${resetToken}`;

    const subject = "There has been a password reset request. Follow the Link";

    const html = `<p> This is the reset link </p>
                    <a href = "${resetUrl}" target="_blank"> Follow this link </a>`;

    try {
      sendMail({
        to: user.email,
        subject,
        html,
      });

      res.status(200).json({
        success: true,
        message: "Password reset link sent to email successfully",
      });
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordTokenExpiry = undefined;
      user.save({ validateBeforeSave: true });
      next(error);
    }
  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (req, res, next) => {
  const { resetPasswordToken } = req.params;
  const {password} = req.body;

  if(!password) {
    res.status(400).json({
        message: 'password is required'
    })
  }

  try {
    // use crypto to hash the reset password token
    const hashedResetPasswordToken = crypto
      .createHash("sha256")
      .update(resetPasswordToken)
      .digest("hex");
  
    const user = await User.findOne({
      resetPasswordToken: hashedResetPasswordToken,
      resetPasswordTokenExpiry: { $gt: Date.now() }
    });
  
    if (!user) {
      const error = new Error("the token or link has expired");
      error.statusCode = 400;
      return next(error);
    }

    user.password= req.body.password;
    user.resetPasswordToken= undefined;
    user.resetPasswordTokenExpiry= undefined;
    // user.markModified('password')

    await user.save();
  
    // await User.findByIdAndUpdate(
    //   user._id,
    //   {
    //     password: req.body.password,
    //     resetPasswordToken: undefined,
    //     resetPasswordTokenExpiry: undefined,
    //   },
    //   { new: true }
    // );
  
    res.status(200).json({
      success: true,
      message: 'password reset successfully'
    });
  } catch (error) {
    next(error);
  }
};

export const loadUser = async (req, res, next) => {
  try {

    const token = req.cookies.jwt;

    if(!token) {
      const error = new Error('You are not logged in');
      error.statusCode = 401;
      return next(error)
    }
    const verifyUser = jwt.verify(token, process.env.JWT_SECRET);
  
    if(!verifyUser) {
      const error = new Error('token invalid');
      error.statusCode = 401;
      return next(error)
    }

    // req.loggedInUser = user;

    const user = await User.findById(verifyUser.id).select('-password');

    if(!user) {
      const error = new Error('the user with this token does not exist');
      error.statusCode = 401;
      return next(error)
    }

    res.status(201).json({
      success: true,
      statusCode: 200,
      user
    })

    next()
  } catch (error) {
    next(error)
  }
}


// function to check the validity of a password reset link
export const checkLink = async (req, res, next) => {
  try {
    const {resetPasswordToken} = req.params;

    // use crypto to hash the reset password token
    const hashedResetPasswordToken = crypto
      .createHash("sha256")
      .update(resetPasswordToken)
      .digest("hex");
  
    const user = await User.findOne({
      resetPasswordToken: hashedResetPasswordToken,
      resetPasswordTokenExpiry: { $gt: Date.now() }
    });
  
    if (!user) {
      const error = new Error("the token or link has expired");
      error.statusCode = 400;
      return next(error);
    }

    res.status(200).json({
      success: true,
      message: 'valid reset link'
    })
  } catch (error) {
    next(error)
  }
}

// function to refresh the token. this function will fetch and renew our token for a logged in user whose token expires
export const refreshToken = async (req, res, next) => {
  const refreshJwt = req.cookies.refreshJwt;

  if(!refreshJwt) {
    const error = new Error('No refresh token');
    error.statusCode = 401;
    return next(error);
  }

  try {
    const decoded = jwt.verify(refreshJwt, process.env.JWT_REFRESH_SECRET);

    const user = await User.findById(decoded.id);

    if(!user) {
      const error = new Error('Invalid refresh token');
      error.statusCode = 401;
      return next(error);
    }

    const newAccessToken = jwt.sign({id: user._id}, process.env.JWT_SECRET, {
      expiresIn: '1m'
    });

    res.cookie("jwt", newAccessToken, {
      maxAge: 1 * 60 * 1000, // 24 * 60 * 60 * 1000 3minutes
      httpOnly: true, // cookie should be set only through the http protocol coming from the backend
      secure: process.env.NODE_ENV === "production",
    });

    res.status(200).json({
      success: true,
      statusCode: 200,
      user
    })
  } catch (error) {
    next(error)
  }
}