const router = require('express').Router();
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { 
  checkPasswordLength, 
  checkUsernameExists, 
  checkUsernameFree,
} = require('../auth/auth-middleware');

router.post('/register', checkPasswordLength, checkUsernameFree, (req, res, next) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 8);

  Users.add({ username, password: hash })
    .then(saved => {
      res.status(201).json(saved)
    })
    .catch(next)
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, req.user.password)) {
    req.session.user = req.user
    res.json({ message: `Welcome ${req.user.username}`})
  } else {
    next({ status: 401, message: 'Invalid credentials'})
  }
  
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

// router.get('/', restricted, async (req, res, next) => {
//   try {
//     const users = Users.find()
//     res.json(users)
//   } catch(err) {
//     next(err)
//   }
// });

module.exports = router;