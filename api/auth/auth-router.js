const router = require('express').Router();
const User = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { 
  checkPasswordLength, 
  checkUsernameExists, 
  checkUsernameFree 
} = require('../auth/auth-middleware');

router.post('/register', checkPasswordLength, checkUsernameFree, (req, res, next) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); 
  user.password = hash;

  User.add(user)
    .then((saved) => {
      res.status(201).json(saved);
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json(err);
    });
})

router.post("/login", checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;

  User.findBy({ username })
    .first()
    .then((user) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({
          message: `Welcome ${user.username}!`,
        });
      } else {
        res.status(401).json({
          message: "Invalid credentials"
        });
      }
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});


router.get("/logout", (req, res, next) => {
  if(req.session.user){
    req.session.destroy(err => {
      if(err) {
        next(err)
      }else{
        res.status(200).json({ message: 'logged out'})
      }
    })
  } else{
    res.status(200).json({ message: 'no session'})
  }
});


module.exports = router;