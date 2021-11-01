const router = require("express").Router();
const model = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require('jsonwebtoken');
// const { JWT_SECRET } = require("../secrets"); // use this secret!
const secrets = require('../secrets')

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
    const credentials = req.body;
    const hash = bcrypt.hashSync(credentials.password, 14);
    credentials.password = hash;
    model.add(credentials)
      .then(success => {
        res.status(201).json(success);
      })
      .catch(error => {
        res.status(500).json({'message': `Server error: ${error}`})
      });
  });


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
    let {username, password} = req.body;

    model.findBy({username})
      .then(user => {
        if(user && bcrypt.compareSync(password, user.password)) {
          const token = generateToken(user);

          res.status(200).json({
            message: `${user.username} is back!`,
            token
          });
        } else {
          res.status(401).json({message: 'Invalid credentials'})
        }
      })
      .catch(error => {
        res.status(500).send(`Error: ${error}`);
      });
});


const generateToken = (user) => {
  console.log(secrets.jwtSecret);
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  };
  const options = {
    expiresIn: '1d'
  };
  return jwt.sign(payload, secrets.jwtSecret, options);
}

module.exports = router;
