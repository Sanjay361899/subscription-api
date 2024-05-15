const User = require('../models/userModel');
const Blacklist = require('../models/blacklist');
const bcrypt = require('bcrypt');
const { validationResult }  = require('express-validator');

const jwt = require('jsonwebtoken');

const userRegister = async(req, res) => {

    try{

        const errors = validationResult(req);

        if(!errors.isEmpty()){
            return res.status(400).json({
                success: false,
                msg: 'Errors',
                errors: errors.array()
            });
        }

        const { name, email, password } = req.body;

        const isExists = await User.findOne({ email });

        if(isExists){
            return res.status(400).json({
                success: false,
                msg: 'Email Already Exists!'
            });
        }

        const hashPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password:hashPassword
        });

        const userData = await user.save();

        return res.status(200).json({
            success: true,
            msg: 'Registered Successfully!',
            user: userData
        });

    }catch(error){
        return res.status(400).json({
            success: false,
            msg: error.message
        });
    }

}

const generateAccessToken = async(user) => {
    const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn:"2h" });
    return token;
}

const loginUser = async(req, res) => {
    try{

        const errors = validationResult(req);

        if(!errors.isEmpty()){
            return res.status(400).json({
                success:false,
                msg:'Errors',
                errors: errors.array()
            });
        }

        const { email, password } = req.body;

        const userData = await User.findOne({ email });

        if(!userData){
            return res.status(401).json({
                success: false,
                msg: 'Email and Password is Incorrect!'
            });
        }

        const passwordMatch = await bcrypt.compare(password, userData.password);

        if(!passwordMatch){
            return res.status(401).json({
                success: false,
                msg: 'Email and Password is Incorrect!'
            });
        }

        const accessToken = await generateAccessToken({ user:userData });

        return res.status(200).json({
            success: true,
            msg: 'Login Successfully!',
            user: userData,
            accessToken: accessToken,
            tokenType: 'Bearer'
        });

    }catch(error){
        return res.status(400).json({
            success: false,
            msg: error.message
        });
    }
}

const userProfile = async(req, res) => {

    try{

        const userData = req.user.user;

        return res.status(200).json({
            success: true,
            msg: 'User Profile Data!',
            data: userData
        });

    }catch(error){
        return res.status(400).json({
            success: false,
            msg: error.message
        });
    }

}

const logout = async(req, res) =>{
    try{

        const token = req.body.token || req.query.token || req.headers["authorization"];

        const bearer = token.split(' ');
        const bearerToken = bearer[1];

        const newBlacklist = new Blacklist({
            token:bearerToken
        });

        await newBlacklist.save();

        res.setHeader('Clear-Site-Data', '"cookies","storage"');
        return res.status(200).json({
            success: true,
            msg: 'You are logged out!'
        });

    }catch(error){
        return res.status(400).json({
            success: false,
            msg: error.message
        });
    }
}

module.exports = {
    userRegister,
    loginUser,
    userProfile,
    logout
}