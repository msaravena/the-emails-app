const { getAll, create, getOne, remove, update, verifyEmail, login, getLoggedUser, resetPassword, newPassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const userRouter = express.Router();

userRouter.route('/')
    .get(getAll)
    .post(create);

userRouter.route('/verify/:code')
    .get(verifyEmail)

userRouter.route('/login')
    .post(login)

userRouter.route('/me')
    .get(verifyJWT, getLoggedUser)

userRouter.route('/reset_password')
    .post(resetPassword)

userRouter.route('/reset_password/:code')
    .put(newPassword)

userRouter.route('/:id')
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(verifyJWT, update);



module.exports = userRouter;