const User = require('../users/users-model');

function restricted(req, res, next) {
  if(req.session.user && req.session) {
    next()
  } else {
    next({
        status: 401,
        message: 'You shall not pass!'
    })
  }
}

const checkUsernameFree = async (req, res, next) => {
  try {
    const rows = await User.findBy({ username: req.body.username })
    if(!rows.length){
      next()
    } else {
      res.status(422).json("Username taken")
    }
  } catch (err) {
    res.status(500).json(`Server error: ${err.message}`)
  }
}

const checkUsernameExists = async(req, res, next) => {
  try {
    const rows = await User.findBy({ username: req.body.username})
    if(rows.length){
      req.userData = rows[0]
      next()
    } else {
      res.status(401).json("Invalid credentials")
    }
  } catch (err) {
    res.status(500).json(`Server error: ${err.message}`)
  }
}

const checkPasswordLength = async(req, res, next) => {
  try {
    const rows = await User.findBy({ username: req.body.password })
    if(rows.length < 3 || !req.body.password){
      res.status(422).json(`Password must be longer than 3 chars`)
    } else {
      next()
    }
  } catch (err) {
    res.status(500).json(`Server error: ${err.message}`)
  }
}

module.exports = {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
  restricted
}