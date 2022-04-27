const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    const { username, password, role_name } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    User.add({ username, password: hash, role_name })
      .then(user => {
        res.status(201).json(user);
      })
      .catch(next)
});


// eslint-disable-next-line no-unused-vars
router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const payload = {
      subject: req.user.id,
      username: req.user.username,
      role_name: req.user.role_name
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" });
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token
    });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

module.exports = router;
