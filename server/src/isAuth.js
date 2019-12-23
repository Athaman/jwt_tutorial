const { verify } = require('jsonwebtoken');

const isAuth = req => {
    const authorization = req.headers['authorization'];
    console.log(authorization);
    if (!authorization) throw new Error("You need to log in");
    //  expect token in 'bearer xxx' but really should do some checks first
    const token = authorization.split(' ')[1];
    const { userId } = verify(token, process.env.ACCESS_TOKEN_SECRET);
    return userId;
};


module.exports = {
    isAuth
};