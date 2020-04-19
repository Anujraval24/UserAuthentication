import express from 'express';

import userController from '../controllers/User';

export default express
    .Router()
    .post('/signup', userController.registerUser)
    .put('/updateUsers', userController.updateUser)
    .get('/findAllUsers', userController.searchUsers)
    .post('/login', userController.login)
    .post('/deleteUser/:id', userController.deleteUser)
    .post('/updatePassword', userController.changePassword)
    .post('/forgotPassword',userController.forgotPassword)
    .post('/resetPassword', userController.resetPassword)