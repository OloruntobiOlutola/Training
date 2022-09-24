const User = require("../models/user-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_EXPIRES_IN, JWT_SECRET } = process.env;

const generateToken = (id) => {
  return jwt.sign({ id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
};

//User signup handler
exports.signUp = async (req, res) => {
  try {
    const { email, fullName, phoneNumber, password, role } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = await User.create({
      email,
      fullName,
      phoneNumber,
      password: hash,
      role,
    });
    const token = await generateToken(user._id);
    res.status(201).json({
      status: "success",
      token,
      data: {
        user,
      },
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error,
    });
  }
};

//User login handler
exports.signIn = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        status: "fail",
        message: "Please enter a valid password and email",
      });
    }
    const user = await User.findOne({ email }).select("+password");
    const confirmPassword = await bcrypt.compare(password, user.password);
    if (!confirmPassword || !user) {
      return res.status(401).json({
        status: "fail",
        message: "Invalid email or password",
      });
    }
    const token = await generateToken(user._id);
    res.status(200).json({
      status: "success",
      token,
      data: {
        user,
      },
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error,
    });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(400).json({
        status: "fail",
        message: `There is no user with the id ${req.params.id}`,
      });
    }
    await User.findByIdAndDelete(req.params.id);
    res.status(204).json({
      status: "successful deleted",
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err,
    });
  }
};

exports.updateUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(400).json({
        status: "fail",
        message: `There is no user with the id ${req.params.id}`,
      });
    }
    const email = req.body.email === undefined ? user.email : req.body.email;
    const phoneNumber =
      req.body.phoneNumber === undefined
        ? user.phoneNumber
        : req.body.phoneNumber;
    const fullName =
      req.body.fullName === undefined ? user.fullName : req.body.fullName;
    const password =
      req.body.password === undefined ? user.password : req.body.password;
    const update = { email, phoneNumber, fullName, password };

    const updatedUser = await User.findByIdAndUpdate(req.params.id, update, {
      new: true,
      runValidators: true,
    });
    res.status(200).json({
      status: "success",
      data: {
        updatedUser,
      },
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error,
    });
  }
};

//Get All Users
exports.getAll = async (req, res) => {
  try {
    const user = await User.find();
    res.status(200).json({
      results: user.length,
      data: {
        user,
      },
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error,
    });
  }
};

//Get One User
exports.getOne = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    res.status(200).json({
      data: {
        user,
      },
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error,
    });
  }
};

exports.protect = async (req, res, next) => {
  if (
    !req.headers.authorization &&
    !req.headers.authorization.startsWith("Bearer")
  ) {
    return res.status(403).json({
      message: "Not logged In",
    });
  }

  let token = req.headers.authorization.split(" ")[1];
  const userJWTData = await jwt.verify(token, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
  const user = await User.findById(userJWTData.id);

  req.user = user;
  next();
};

exports.restrictTo = (...roles) => {
  return async (req, res, next) => {
    if (!req.user.role.includes(...roles)) {
      return res.status(401).json({
        message: "You are not authorized to do this",
      });
    }
    next();
  };
};
