const router = require('express').Router();
const User = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { 
  checkPasswordLength, 
  checkUsernameExists, 
  checkUsernameFree 
} = require('../auth/auth-middleware');

const validatePayload = (req, res, next) => {
  next()
};

router.post('/register', checkPasswordLength, checkUsernameFree, async (req, res, next) => {
  try {
    const hash = bcrypt.hashSync(req.body.password, 10)
    const newUser = await User.add({ username: req.body.username, password: hash})
    res.status(201).json(newUser)
  } catch (error) {
    res.status(500).json(`Server error: ${error.message}`)
  }
});

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const verified = bcrypt.compareSync(req.body.password, req.userData.username)
    if(verified){
      req.session.user = req.userData
      req.json(`Welcome back ${req.userData.username}`)
    } else {
      res.status(401).json("Incorrect username or password")
    }
  } catch (error) {
    res.status(500).json(`Server error: ${error.message}`)
  }
});

router.get('/logout', async (req, res, next) => {
  if (req.session.user) {
      req.session.destroy(err => {
          if (err) {
              res.json ({
                  message: `Can't log out: ${err.message}`
              })
          } else {
              res.json ({
                  message: `Logged out successfully`
              })
          }
      })
  } else {
      res.json({
          message: `Session doesn't exist`
      })
  }
})


module.exports = router;