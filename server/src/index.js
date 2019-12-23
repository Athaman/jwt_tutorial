require('dotenv/config');

const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash, compare } = require('bcryptjs');

const { fakeDB } = require('../db/fakeDB');
const { 
    createAccessToken,
    createRefreshToken,
    sendAccessToken, 
    sendRefreshToken
} = require('./tokens');
const { isAuth } = require('./isAuth');

//  1. register a user 
//  2 login a user 
//  3 logout a user 
//  4 setup protected route 
//  5 get a new accesstoken with a refresh token

const server = express();

//  use express middleware for easier cookie handling 
server.use(cookieParser());

server.use(
    cors({
        origin: 'http://localhost:3000',
        credentials: true
    })
);

//  needed to be able to read body data 
server.use(express.json()); // to support json bodies 
server.use(express.urlencoded({ extended: true })); // support url encoded bodies


//  1 register 
server.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        //  1 check if user exists
        const user = fakeDB.find(user => user.email === email);
        if (user) throw new Error('user already exists');
        // otherwise make the user
        const hashedPassword = await hash(password, 10);
        // and 'push' to the 'database'
        fakeDB.push({ id: fakeDB.length, email, hashedPassword });
        res.send({ message: 'User created' });

        console.log(fakeDB);

    } catch (err) {
        console.log(err);
        res.send({
            error: `something done goofed: ${err.message}`
        });
    }
});

//  Login a user
server.post('/login', async (req, res) => {
    const { email, password } = req.body; 

    try {
        //  find the user in the 'database'
        const user = fakeDB.find(user => user.email === email);
        if (!user) throw new Error("User does not exist");
        // compare the hashed password to the one in the 'db'
        const valid = await compare(password, user.password);
        if (!valid) throw new Error("Password not correct");
        //  create refresh and access tokens 
        const accesstoken = createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);
        // put the refreshtoke in the 'database'
        user.refreshtoken = refreshtoken;
        console.log(fakeDB);
        //  send token. refreshtoken as a cookie and accesstoken as regular response
        sendRefreshToken(res, refreshtoken);
        sendAccessToken(req, res, accesstoken)
    } catch (err) {
        res.send({
            error: `oh no, the login path broke: ${err.message}`
        })
    }
});

//  logout a user 
server.post('/logout', (req, res) => {
    res.clearCookie('refreshtoken', { path: '/refresh_token' });
    return res.send({
        message: 'logged out'
    });
});

//  a protected route 
server.post('/protected', async (req, res) => {
    try {
        const userId = isAuth(req);
        if (userId !== null) {
           res.send({
               data: 'this is secret data'
           }) 
        }
    } catch (err) {
        console.log(err);
        res.send({
            error: `something broke behind the protection: ${err.message}`
        })
    }
});

//  get a new access token from the refresh token 
server.post('/refresh_token', (req, res) => {
    const token = req.cookies.refreshtoken;
    //  if no token 
    if(!token) return res.send({ accesstoken: ''});
    // we have a token 
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
        return res.send({ accesstoken: '' });
    }
    // token valid check for user 
    const user = fakeDB.find(user => user.id === payload.userId);
    if (!user) return res.send({ accesstoken: '' });
    // user exist check for refreshtoken
    if (user.refreshtoken !== token) {
        return res.send({ accesstoken: ''});
    }

    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    user.refreshtoken = refreshtoken;
    // all good, send the new refresh and access tokens 
    sendRefreshToken(res, refreshtoken);
    return res.send({ accesstoken })
});

server.listen(process.env.PORT, () => 
    console.log(`Server listening on port ${process.env.PORT}`)
);