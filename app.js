//------------------------------
// Initialize
//------------------------------
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const cors = require("cors");
const crypto = require("crypto");
const cryptoRandomString = require("crypto-random-string");
const cookieParser = require('cookie-parser');
const cookieSession = require('cookie-session');
const keygrip = require("keygrip");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const ms = require("ms");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const NodeRSA = require("node-rsa");
const uid = require("uid");
const pug = require("pug");
const path = require("path");
const { oneOf, body, query, validationResult } = require("express-validator");

const Config = require("./config/config.json");

const PUBLIC_KEY = fs.readFileSync(__dirname + '/config' + '/public.key');
const PRIVATE_KEY = fs.readFileSync(__dirname + '/config' + '/private.key');

const HOST = Config.Host;
const DB_HOST = Config.DB_Host;
const DB_NAME = Config.DB_Name;
const PORT = Config.Port;

const HOUR_MS = 360000;
const DAY_MS = (1000 * 60 * 60 * 24);
const MAX_REFRESH_TOKEN_LIFE_TIME = (DAY_MS * 7);
const REFRESH_TOKEN_RANDOM_LENGTH = Config.RefreshTokenRandomLength;

const CLIENT_WHITELIST = Config.ClientWhiteList;

let User;
let UserSchema;

let CodeChallenge;
let CodeChallengeSchema;

let Client;
let ClientSchema;

let RefreshToken;
let RefreshTokenSchema;

mongoose.connect(DB_HOST, {
    useCreateIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    dbName: DB_NAME
});

let db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log("Connected to database...");

    UserSchema = new mongoose.Schema({
        username: String,
        fullname: String,
        hash: String,
        joinDate: String,
        verifyHash: String,
        isVerified: Boolean
    });

    CodeChallengeSchema = new mongoose.Schema({
        userID: mongoose.Types.ObjectId,
        hash: String,
        hashMethod: String,
        expireDate: Date
    });

    ClientSchema = new mongoose.Schema({
        name: String,
        secretKey: String,
        publicKey: String
    });

    RefreshTokenSchema = new mongoose.Schema({
        userID: mongoose.Types.ObjectId,
        clientID: mongoose.Types.ObjectId,
        signature: String,
        expireDate: Date
    });

    User = mongoose.model('User', UserSchema);
    CodeChallenge = mongoose.model('CodeChallenge', CodeChallengeSchema);
    Client = mongoose.model('Client', ClientSchema);
    RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);
});

// Keep removing an expire code code challenge in DB
setInterval(() => {
    let now = Date.now();
    CodeChallenge.deleteMany(
    {
        expireDate: { $lt: now }
    }, (err) => { 
        if (err)
            console.log(err)
        });
}, HOUR_MS);

// Keep removing an expire refresh token
setInterval(() => {
    let now = Date.now();
    Client.deleteMany(
    {
        expireDate: { $lt: now }
    }, (err) => { 
        if (err)
            console.log(err)
        });
}, DAY_MS);

/*
function generateKeyPair() {
    const key = new NodeRSA({b: 512});
    key.generateKeyPair(512);

    let public = key.exportKey("pkcs1-public");
    let private = key.exportKey("pkcs1-private");
    let encrpyted = key.encryptPrivate("iO3quoYg265hlzq30E8RelQc0LOKle4R0yk6CMbgeHgGNcm_mR", "base64", "utf8");

    const fs = require('fs');

    fs.writeFile('gameserverPublic.pem', public, function (err) {

    });

    fs.writeFile('gameserverPrivate.pem', private, function (err) {

    });

    fs.writeFile('gameserverSecret.pem', encrpyted, function (err) {

    });
}
*/

// generateKeyPair();

//header for resource reqeust (authen) 
//Authorization: Bearer     eyJhbGciOiJIUzI1NiIXVCJ9TJV...r7E20RMHrHDcEfxjoYZgeFONFh7HgQ

const EMAIL = Config.Email;
const SUBJECT = {
    verify_account: "Shooting Game : Verify your account",
    reset_password: "Shooting Game : Reset your password"
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: EMAIL,
    pass: Config.EmailPassword
  }
});

let app = express();

app.use(cors({ origin: true }));
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(express.static("public"))

app.use(cookieParser());
app.use(cookieSession({
  name: 'session',
  keys: Config.CookieKeyList
}));

//Test <--- replace with DB
let users = [];

//------------------------------
// Request Handler
//------------------------------
//TODO : access token good practice
// {
//   "iss": "https://YOUR_DOMAIN/", //<--- who sign this token
//   "sub": "auth0|123456",
//   "aud": [
//     "my-api-identifier", //<-- resource provider
//     "https://YOUR_DOMAIN/userinfo" //<-- website, which end point to allow <-- in game (which resource provider end point to allow)
//   ],
//   "azp": "YOUR_CLIENT_ID", //<--- client id that request
//   "exp": 1489179954, //<-- libray handl for us
//   "iat": 1489143954, //<-- libray handl for us
//   "scope": "openid profile email address phone read:appointments" //<-- read:profile(game client) <--- write:progress (seperate document with _id link (user))
// }

function generateAccessToken(info, lifeTime) {
    let payload = {
        uid: uid(12),
        iss: HOST,
        sub: info.sub,
        name: info.name,
        scope: info.scope || "read"
    };

    let resultExpire = lifeTime || "1h";
    let access_token =  jwt.sign(payload, PRIVATE_KEY, { algorithm: "RS256", expiresIn: resultExpire });

    let result = {
        access_token: access_token,
        expires_in: ms(resultExpire)
    }

    return result;
}

function generateRefreshToken(userID) {
    const randomString = cryptoRandomString({length: REFRESH_TOKEN_RANDOM_LENGTH});
    const secret = (userID + "." + randomString);

    const key = new NodeRSA({b: 512});

    key.importKey(PUBLIC_KEY);
    key.importKey(PRIVATE_KEY);

    key.setOptions({encryptionScheme: 'pkcs1'});

    const signature = key.encryptPrivate(secret, "base64", "utf8");
    return signature;
}

function generateIDToken(userID, callback, lifeTime) {
    User.findById({ _id: userID }, (err, doc) => {
        if (err) {
            callback(err);
        }

        let info = {
            iss: HOST,
            sub: doc._id,
            name: doc.fullname,
            email: doc.username,
            isVerified: doc.isVerified
        };

        let resultExpire = lifeTime || "10m";
        let token = jwt.sign(info, PRIVATE_KEY, { algorithm: "RS256", expiresIn: resultExpire });

        callback(err, token);
    });
}

function decryptRefreshToken(token) {
    try {
        const key = new NodeRSA({b: 512});

        key.importKey(PUBLIC_KEY);
        key.importKey(PRIVATE_KEY);

        key.setOptions({encryptionScheme: 'pkcs1'});

        const secret = key.decryptPublic(token, "utf8");
        return secret;
    }
    catch (err) {
        return undefined;
    }
}

function addRefreshToken(token, clientID, userID, callback) {
    let userObjectID = mongoose.Types.ObjectId(userID);
    let clientObjectID = mongoose.Types.ObjectId(clientID);

    try {
        let info = {
            userID: userObjectID,
            clientID: clientObjectID,
            signature: token,
            expireDate: new Date(Date.now() + MAX_REFRESH_TOKEN_LIFE_TIME)
        }

        let newToken = new RefreshToken(info);
        newToken.save(err => {
            if (err) {
                throw err;
            }
            callback(err, token);
        });
    }
    catch (err) {
        console.log(err);
        callback(err, undefined);
    }
}

function updateRefreshToken(token, oldToken, clientID, userID, callback) {
    let userObjectID = mongoose.Types.ObjectId(userID);
    let clientObjectID = mongoose.Types.ObjectId(clientID);
    let NOW = new Date();

    try {
        RefreshToken.findOneAndUpdate({
            userID: userObjectID,
            clientID: clientObjectID,
            signature: oldToken,
            expireDate: {
                $gte : NOW
            }
        },
        {
            $set: {
                signature: token
            }
        },
        {
            new: true,
            rawResult: true
        }, (err, res) => {
            if (err) {
                callback(err, undefined);
            }
            else if (res.lastErrorObject.n <= 0) {
                callback(err, undefined);
            }
            else {
                callback(err, token);
            }
        });
    }
    catch (err) {
        console.log(err);
        callback(err, undefined);
    }
}

function removeRefreshToken(token, clientID, userID, callback) {
    let userObjectID = mongoose.Types.ObjectId(userID);
    let clientObjectID = mongoose.Types.ObjectId(clientID);

    try {
        RefreshToken.deleteMany({
            userID: userObjectID,
            clientID: clientObjectID,
            signature: token,
        }, (err, result) => {
            if (err) {
                throw err;
            }
            callback(err, result);
        });
    }
    catch (err) {
        console.log(err);
        callback(err, undefined);
    }
}

function rotateRefreshToken(client_id, oldToken, userID, callback) {
    const newRefreshToken = generateRefreshToken(userID);
    try {
        updateRefreshToken(newRefreshToken, oldToken, client_id, userID, (err, saveToken) => {
            if (err) {
                callback(err, undefined);
            }
            else if (saveToken == undefined) {
                callback(err, undefined);
            }
            else {
                callback(err, saveToken);
            }
        });
    }
    catch (err) {
        console.log(err);
        callback(err, undefined);
    }
}

function handleTokenRequest(req, res) {
    switch (req.body.grant_type)
    {
        case "password":
            handleGrantTypeOfPassword(req, res);
            break

        case "authorization_code":
            handleGrantTypeOfAuthorizationCode(req, res);
            break;
        
        case "client_credentials":
            handleGrantTypeOfClientCredential(req, res);
            break;

        case "refresh_token":
            handleGrantTypeOfRefreshToken(req, res);
            break;
        
        default:
            throw "Error..";
    }
}

function handleGrantTypeOfPassword(req, res) {

    let query = User.where({ username: req.body.username.toLowerCase() });

    query.findOne((err, user) => {
        if (err || user == undefined) {
            res.status(404).send();
            return;
        }

        bcrypt.compare(req.body.password, user.hash, (err, same) => {
            if (err) {
                res.status(404).send();
                return;
            }

            if (same) {
                try {
                    let info = {
                        sub: user._id,
                        name: user.fullname,
                        roles: "user",
                        scope: req.body.scope || "read"
                    }

                    let generateResult = generateAccessToken(info);

                    let access_token = generateResult.access_token;
                    let expires_in = generateResult.expires_in;

                    let refresh_token = generateRefreshToken(user._id);

                    addRefreshToken(refresh_token, req.body.client_id, user._id, (err, token) => {
                        if (err) {
                            throw err;
                        }

                        let result = {
                            auth: true,
                            token_type: "bearer",
                            access_token: access_token,
                            refresh_token: refresh_token,
                            scope: info.scope,
                            expires_in: expires_in
                        };

                        res.header("Cache-Control", "no-store");
                        res.header("Pragma", "no-cache");

                        res.status(200).json(result);

                    });
                }
                catch (err) {
                    console.log(err);
                    res.status(401).send({ auth: false, message: 'Failed to authenticate token.' });
                }
            }
            else {
                res.status(401).send({ auth: false, message: 'Failed to authenticate token.' });
            }
        });
    });
}

function handleGrantTypeOfAuthorizationCode(req, res) {
    jwt.verify(req.body.code, PUBLIC_KEY, (err, payload) => {
        if (err) {
            res.status(401).send({ auth: false, message: 'Failed to authenticate token.' });
            return;
        }

        let code_challenge_method = "sha256";
        let attemptCodeVerifierHash = crypto.createHash(code_challenge_method).update(req.body.code_verifier).digest("hex").toString();

        let query = CodeChallenge.where({
            userID: payload.sub,
            hash: attemptCodeVerifierHash
        });

        query.findOneAndRemove((err, storeHash) => {
            if (err || storeHash == undefined) {
                res.status(401).send({ auth: false, message: 'Failed to authenticate token.' });
                return;
            }

            try {
                let info = {
                    sub: storeHash.userID,
                    name: payload.name,
                    roles: "user",
                    scope: req.body.scope || "read"
                }

                let generateResult = generateAccessToken(info, "1h");

                let access_token = generateResult.access_token;
                let expires_in = generateResult.expires_in;

                let refresh_token = generateRefreshToken(storeHash.userID);

                let result = {
                    token_type: "bearer",
                    refresh_token: refresh_token,
                    scope: info.scope,
                    expires_in: expires_in
                }

                addRefreshToken(refresh_token, req.body.client_id, storeHash.userID, (err, token) => {
                    if (err) {
                        console.log(err);
                        throw err;
                    }

                    result.auth = true;
                    result.access_token = access_token;

                    if (req.body.response_type == "id_token") {
                         generateIDToken(storeHash.userID, (err, token) => {

                            if (err) {
                                result.id_token = undefined;
                            }
                            else {
                                result.id_token = token;
                            }

                            res.header("Cache-Control", "no-store");
                            res.header("Pragma", "no-cache");

                            res.status(200).json(result);
                        });
                    }
                    else {
                        res.header("Cache-Control", "no-store");
                        res.header("Pragma", "no-cache");

                        res.status(200).json(result);
                    }
                });
            }
            catch (err) {
                console.log(err);
                res.status(401).send({ auth: false, message: 'Failed to authenticate token.' });
            }
        });
    });
}

function handleGrantTypeOfClientCredential(req, res) {
    try {
        let isValidSignature = isClientCredentialValid(req.body.client_id, req.body.client_secret);

        if (isValidSignature == false) {
            throw "Invalidate client secret key of client id : " + req.body.client_id;
        }

        let info = {
            iss: HOST,
            sub: req.body.client_id,
            roles: "user",
            scope: req.body.scope || "read",
        }

        let generateResult = generateAccessToken(info, "12h");

        let access_token = generateResult.access_token;
        let expires_in = generateResult.expires_in;

        let result = {
            auth: true,
            token_type: "bearer",
            access_token: access_token,
            expires_in: expires_in,
            scope: info.scope
        };

        res.header("Cache-Control", "no-store");
        res.header("Pragma", "no-cache");

        res.status(200).json(result);
    }
    catch (err) {
        console.log(err);
        res.status(403).json({ auth: false });
    }
}

function handleGrantTypeOfRefreshToken(req, res) {
    try {
        if (req.body.client_secret) {

            let isValidSignature = isClientCredentialValid(req.body.client_id, req.body.client_secret);

            if (isValidSignature == false) {
                throw "Invalidate client secret key of client id : " + req.body.client_id;
            }
        }

        let secret = decryptRefreshToken(req.body.refresh_token);

        if (secret == undefined) {
            let message = "Invalid refresh token request has been push to this server...\n" + "Signature : " + req.body.refresh_token + "\nClient id: " + req.body.client_id;
            throw message;
        }

        let userID = secret.split(".")[0];

        rotateRefreshToken(req.body.client_id, req.body.refresh_token, userID, (err, token) => {
            if (err || token == undefined) {
                console.log(err);
                res.status(403).send();
                return;
            }

            let refresh_token = token;

            let info = {
                iss: HOST,
                sub: req.body.user_id,
                roles: "user",
                scope: req.body.scope || "read",
            }

            let generateResult = generateAccessToken(info, "1h");

            let access_token = generateResult.access_token;
            let expires_in = generateResult.expires_in;

            let result = {
                auth: true,
                token_type: "bearer",
                access_token: access_token,
                expires_in: expires_in,
                refresh_token: refresh_token,
                scope: info.scope
            };

            res.header("Cache-Control", "no-store");
            res.header("Pragma", "no-cache");

            res.status(200).json(result);
        });
    }
    catch (err) {
        console.log(err);
        res.status(403).send();
    }
}

function sendVerificationEmail(info, callback) {
    let verifyToken = jwt.sign({
        id: info.id,
        hash: info.hash
    }, PRIVATE_KEY, { algorithm: "RS256", expiresIn: "10m" });

    let urlToVerifyAccount = HOST + "/user/verify?id=" + info.id +
                            "&hash=" + info.hash + 
                            "&token=" + verifyToken;

    if (info.redirect_uri) {
        urlToVerifyAccount += "&redirect_uri=" + info.redirect_uri;
    }

    let html = "<b>Your account : " + info.username + "</b>" +
                '<p>Click <a href="' + urlToVerifyAccount + '">here</a> to verify account.</p>';

    let mailOptions = {
        from: EMAIL,
        to: info.username,
        subject: SUBJECT.verify_account,
        html: html
    };

    transporter.sendMail(mailOptions, (err, mailInfo) => {
        callback(err, mailInfo);
    });
}

function isClientCredentialValid(clientID, clientSignature) {
    Client.findById({ _id: clientID }, (err, doc) => {
        try {
            if (err)
                throw err;
        
            const key = new NodeRSA({b: 512});

            if (doc.publicKey == null || undefined)
                return false;

            key.importKey(doc.publicKey, "pkcs1-public");
            key.setOptions({encryptionScheme: 'pkcs1'});

            const secret = key.decryptPublic(clientSignature, "utf8");

            const isValid = (doc.secretKey == secret);
            return isValid;
        }
        catch (err) {
            console.log(err);
            return false;
        }
    });
}

//Login page (OAuth2.0 Authorization code flow)
app.get("/auth",
    [
        query("response_type").equals("code"),
        query("client_id").isIn(CLIENT_WHITELIST),
        query("code_challenge").exists(),
        query("code_challenge_method").exists(),
        query("state").exists(),
        query("redirect_uri").exists(),
    ],
(req, res) => {
    try {
        validationResult(req).throw();
        res.sendFile(path.join(__dirname + "/index.html"));
    }
    catch (error) {
        res.status(400).send();
    }
});

app.post("/auth",
[
    body("username").isEmail(),
    body("password").exists(),
    body("redirect_uri").exists(),
    body("code_challenge").exists(),
    body("code_challenge_method").exists(),
    body("state").exists()
],
(req, res) => {
    try {
        validationResult(req).throw();
        
        let query = User.where({ username: req.body.username.toLowerCase() });

        query.findOne((err, user) => {
            if (err || user == undefined) {
                res.status(401).send();
                return;
            }

            bcrypt.compare(req.body.password, user.hash, (err, same) => {
                if (err || !same) {
                    res.status(401).send();
                    return;
                }

                let newCodeChallenge = new CodeChallenge({
                    userID: user._id,
                    hash: req.body.code_challenge,
                    hashMethod: req.body.code_challenge_method,
                    expireDate: new Date(Date.now() + 60000)
                });

                newCodeChallenge.save((err) => {
                    if (err) {
                        console.log(err);
                        res.status(500).send();
                        return;
                    }

                    let authCode = jwt.sign({
                        sub: user._id,
                        iss: user.fullname,
                    }, PRIVATE_KEY, { algorithm: "RS256", expiresIn: "1m" });

                    let info = {
                        code: authCode,
                        state: req.body.state,
                        redirect_uri: req.body.redirect_uri,
                    };

                    res.status(200).json(info);
                });
            });
        });
    }
    catch (error) {
        console.log(error);
        res.status(400).send();
    }
});

//Register page
app.get("/signup", [
    query("redirect_uri").optional()
],
(req, res) => {
    req.session.redirect_uri = req.query.redirect_uri;
    res.sendFile(path.join(__dirname + "/register.html"));
});

//Register new user
app.post("/signup", [
    body("username").isEmail(),
    body("password").isLength({ min: 5 }),
    body("fullname").exists(),
    body("redirect_uri").optional()
], (req, res) => {
    try {
        validationResult(req).throw();

        let query = User.where({ username: req.body.username.toLowerCase() });

        query.findOne((err, user) => {
            if (err || user != undefined) {
                res.status(409).send();
                return;
            }

            bcrypt.genSalt(12, (err, salt) => {
                if (err) {
                    throw 409;
                }
                else {
                    let info = {
                        username: req.body.username.toLowerCase(),
                        fullname: req.body.fullname,
                        joinDate: new Date().toISOString(),
                        verifyHash: uid(64),
                        isVerified: false
                    }

                    bcrypt.hash(req.body.password, salt, (err, hash) => {
                        if (err) {
                            throw 409;
                        }
                        else {
                            info.hash = hash;
                            let newUser = new User(info)

                            newUser.save((err) => {
                                if (err)
                                    res.status(500).send();

                                res.status(201).send();

                                let verifyEmailInfo = {
                                    id: newUser._id,
                                    username: newUser.username,
                                    hash: newUser.verifyHash,
                                }

                                if (req.body.redirect_uri) {
                                    verifyEmailInfo.redirect_uri = req.body.redirect_uri;
                                }
                                else {
                                    verifyEmailInfo.redirect_uri = req.session.redirect_uri;
                                }

                                sendVerificationEmail(verifyEmailInfo, (err, mailInfo) => {
                                    if (err)
                                        console.log(err);
                                });
                            });
                        }
                    });
                }
            });
        });
    }
    catch (error) {
        res.status(400).send();
    }
});

//Sent a new verify account endpoint
app.post("/user/verify/new", [
    body("username").isEmail(),
    body("redirect_uri").optional()
],
(req, res) => {
    try {
        validationResult(req).throw();

        let query = User.where({ username: req.body.username.toLowerCase() });

        query.findOne((err, user) => {
            if (err || user == undefined) {
                res.status(404).send();
                return;
            }

            if (user.isVerified) {
                res.status(204).send();
                return;
            }

            user.verifyHash = uid(64)

            user.save((err) => {
                if (err) {
                    res.status(500).send();
                    return;
                }

                res.status(200).send();

                let verifyEmailInfo = {
                    id: user._id,
                    username: user.username,
                    hash: user.verifyHash,
                    redirect_uri: req.body.redirect_uri
                }

                sendVerificationEmail(verifyEmailInfo, (err, mailInfo) => {
                    if (err)
                        console.log(err);
                });
            });
        });
    }
    catch (error) {
        res.status(400).send();
    }
});

//Verify Account (checks with verify token)
app.get("/user/verify", [
    query("id").exists(),
    query("hash").exists(),
    query("token").exists(),
    query("redirect").optional()
],
(req, res) => {
    try {
        validationResult(req).throw();

        jwt.verify(req.query.token, PUBLIC_KEY, (err, payload) => {
            let notValid = (err) || (payload.id != req.query.id) | (payload.hash != req.query.hash);

            if (notValid) {
                res.status(401).send();
                return;
            }

            User.findById(req.query.id, (err, user) => {
                if (err || user == undefined) {
                    res.status(404).send();
                    return;
                }

                user.verifyHash = undefined;
                user.isVerified = true;

                user.save((err) => {
                    if (err) {
                        res.status(500).send();
                        return;
                    }

                    if (req.query.redirect_uri) {
                        res.redirect(req.query.redirect_uri);
                    }
                    else {
                        res.status(200).send();
                    }
                });
            });
        });
    }
    catch (error) {
        res.status(400).send();
    }
});

//TODO
//Forget password -> sent password reset url to email (along with short live token)
app.post("/user/forgetpassword", [
    body("username").isEmail(),
    body("redirect_uri").isURL()
], (req, res) => {
    try {
        validationResult(req).throw();

        //TODO
        //sent valid url along with token to specify email

        //if account not found -> invalid 404

        let isFound = users.find(element => element.username == req.body.email);

        if (isFound) {
            let token = jwt.sign({
                userID: 0, //get from db
                hash: uid(64)
            }, PRIVATE_KEY, { algorithm: "RS256", expiresIn: "10m" })

            let info = {
                id: 0, // get user id from db
                hash: uid(64),
                token: token
            }

            element.resetPasswordHash = info.hash;

            // example
            // let urlToSetANewPassword = "host/user/resetpassword?id=0&hash={{resetPasswordHash}}&token=slkdjflsjdfklsjkdlfjsldfkjl"
            //send url of reset password email here...

            res.status(200).send();
        }
        else {
            res.status(404).send();
        }
    }
    catch (error) {
        res.status(400).send();
    }
});

//Verify token, if valid -> redirect to a url that provide reset a new password
app.get("/user/forgetpassword", [
    query("id").exists(),
    query("hash").exists(),
    query("token").exists(),
    query("redirect").optional().isURL()
],
(req, res) => {
    try {
        validationResult(req).throw();

        res.status(200).send();
    }
    catch (error) {
        res.status(400).send();
    }
});

app.post("/token", oneOf([
    [
        body("grant_type").equals("password"),
        body("username").isEmail(),
        body("client_id").isIn(CLIENT_WHITELIST),
        body("password").isLength({ min: 5 }),
    ],
    [
        body("grant_type").equals("authorization_code"),
        body("client_id").isIn(CLIENT_WHITELIST),
        body("code").exists(),
        body("code_verifier").exists(),
        body("redirect_uri").optional(),
        body("response_type").optional().equals("id_token")
    ],
    [
        body("grant_type").equals("client_credentials"),
        body("client_id").isIn(CLIENT_WHITELIST),
        body("client_secret").exists()
    ],
    [
        body("grant_type").equals("refresh_token"),
        body("refresh_token").exists(),
        body("client_id").isIn(CLIENT_WHITELIST),
        body("client_secret").optional(),
        body("scope").optional()
    ]
]),
(req, res) => {
    try {
        validationResult(req).throw();
        handleTokenRequest(req, res);
    }
    catch (error) {
        console.log(error);
        res.status(400).send();
    }
});

app.post("/token/revoke", [
    body("refresh_token").exists(),
    body("client_id").isIn(CLIENT_WHITELIST),
    body("user_id").exists(),
    body("client_secret").optional(),
],
(req, res) => {
    try {
        validationResult(req).throw();

        if (req.body.client_secret) {
            isSignatureValid = isClientCredentialValid(req.body.client_id, req.body.client_secret);

            if (isSignatureValid == false) {
                throw "Signature not valid..."
            }
        }

        removeRefreshToken(req.body.refresh_token, req.body.client_id, req.body.user_id, (err, result) => {
            if (err) {
                throw err;
            }
            res.status(200).json(result);
        });
    }
    catch (error) {
        console.log(error);
        res.status(400).send();
    }
});

app.get("/user/publicinfo", [
    query("client_id").isIn(CLIENT_WHITELIST),
    oneOf([
        [
            query("user_id").exists()
        ],
        [
            query("email").isEmail()
        ]
    ])
],
(req, res) => {
    try {
        validationResult(req).throw();

        if (req.query.user_id) {

            User.find().where('_id').in(req.query.user_id).exec((err, doc) => {
                if (err) {
                    res.status(500).send();
                    return;
                }

                if (doc == undefined) {
                    res.status(404).send();
                    return;
                }

                let info = [];

                for (let element of doc) {
                    info.push({
                        id: element._id,
                        name: element.fullname,
                        joinDate: element.joinDate
                    })
                }

                res.status(200).json(info);
            });
        }
        else if (req.query.email) {
            let email = req.query.email.toLowerCase();

            User.findOne({ username: email }, (err, doc) => {
                if (err) {
                    res.status(500).send();
                    return;
                }

                if (doc == undefined) {
                    res.status(404).send();
                    return;
                }

                let info = {
                    id: doc._id,
                    name: doc.fullname,
                    joinDate: doc.joinDate
                }

                res.status(200).json(info);
            });
        }
    }
    catch (error) {
        console.log(error);
        res.status(400).send();
    }
});

app.use((req, res) => {
    res.status(400).send();
});

app.listen(PORT, () => {
    console.log("Server start at port : " + PORT);
});
