const {Router} = require('express');
const jwt = require('jsonwebtoken');
const config = require('config');
const bcrypt = require('bcrypt');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();

router.post(
  '/register',
  [
    check('email', 'Некорректный email').isEmail(),
    check('password', 'Некорректный пароль').isLength({min: 6}),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res
          .status(400)
          .json({errors: errors.array(), message: 'Некорректные данные'});
      }
      const {email, password} = req.body;
      const candidate = await User.findOne({email});

      if (candidate) {
        return res
          .status(400)
          .json({message: 'Такой пользователь уже существует'});
      }

      const hashPass = await bcrypt.hash(password, 12);
      const user = new User({email, password: hashPass});
      await user.save();

      res.status(201).json({message: 'Пользователь создан'});
    } catch (error) {
      res.status(500).json({message: 'Что-то не так'});
    }
  }
);

router.post(
  '/login',
  [
    check('email', 'Некорректный email').normalizeEmail().isEmail(),
    check('password', 'Ввкдите пароль').exists(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Некорректные данные при входе',
        });
      }

      const {email, password} = req.body;
      const user = await User.findOne({email});

      if (!user) {
        return res.status(400).json({message: 'Пользователь не найден'});
      }

      const ismatch = await bcrypt.compare(password, user.password);
      if (!ismatch) {
        return res.status(400).json({message: 'Неверный пароль'});
      }

      const token = jwt.sign({userid: user.id}, config.get('jwtSecret'), {
        expiresIn: '1h',
      });
      res.json({token, userid: user.id})
    } catch (error) {
      res.status(500).json({message: 'Что-то не так'});
    }
  }
);

module.exports = router;
