/* const sqlite3 = require('sqlite3')*/

const path = require("path");
const sqlite3 = require('sqlite3')
const express = require('express');
let app = express();
const sqlite = require('sqlite3').verbose();
const session = require('express-session');
const rateLimit = require('express-rate-limit')
const sharp = require('sharp');
const { render } = require('ejs');
const { urlencoded } = require('express');
const getRawBody = require('raw-body');
const contentType = require('content-type');
const toobusy = require('toobusy-js')
const limiter = require('rate-limiter');
const csrf = require('csurf');//For CSRF
var cookieParser = require('cookie-parser'); //For CSRF
var bodyParser = require('body-parser'); //For CSRF
var xss = require('xss');//For XSS / sanitization

// smtp email server for sending 6 digit code -----------------------------------------------------------------------------
require('dotenv').config();
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;
// ------------------------------------------------------------------------------------------------------------------------

const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false
})



const truncate = require('truncate');
const bcrypt = require('bcrypt');
const saltRounds = 16;



// global captcha array
let captchaArray = '';


app = express();
app.use(express.static('public'));
app.use(urlencoded({ extended: false }));
app.set("port", process.env.PORT || 8000);
app.use(express.static('captcha'))



app.listen(app.get("port"), function () {
    //console.log("Server started on port " + app.get("port"));
});

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true,
    name: "id",//hides the name of session cookie name 'connect.sid' as details of app are obfuscated
    cookie: {
        maxAge: 86400000, //One day min for cookie time to live
        path: "/",
        //secure: true, //prevents leaking of session cookie over insecure requests but eliminates ability to
        //send session cookie on each request because this blog is not currently HTTPS
        httpOnly: true, //Disallow client side javascript to see the cookie
        sameSite: true // cookie will only be attached to requests from the same site
    }
}));

var bodyParser = require('body-parser');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }))

const db = new sqlite3.Database(path.join(__dirname, "database.sqlite"), sqlite3.OPEN_READWRITE, (err) => {
    if (err) return console.error(err.message);
});

// JSON SETTINGS
const sessionconfig = require('./config/session.json');
const { oauth2 } = require("googleapis/build/src/apis/oauth2");
//const {oauth2} = require("googleapis/build/src/apis/oauth2");
const { NONAME } = require("dns");
const { redis } = require("googleapis/build/src/apis/redis");


// Session
// Change the session secret key later
app.use(session({
    secret: sessionconfig.secret,
    resave: sessionconfig.resave,
    saveUninitialized: sessionconfig.saveUninitialized
}));

//Further DDOS mititgation - if server is too busy then send a too busy message instead of overloading the server and taking it down
// works by comparing average time of requests
app.use(function (req, res, next) {
    if (toobusy()) {
        // log if you see necessary
        res.send(503, "Server Too Busy");
    } else {
        next();
    }
});

var csrfProtection = csrf({ cookie: true });
var parseForm = bodyParser.urlencoded({ extended: false });
app.use(cookieParser());

sql = 'SELECT name FROM users WHERE username == "aking"'

const runData = (theQuery) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run(theQuery, [], (err, rows) => {
                if (err)
                    reject(err)
                resolve(rows)
            })
        });
    })
}

const allData = (theQuery) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.all(theQuery, [], (err, rows) => {
                if (err)
                    reject(err)
                resolve(rows)
            })
        });
    })
}

const getData = (theQuery) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.get(theQuery, [], (err, rows) => {
                if (err)
                    reject(err)
                resolve(rows)
            })
        });
    })
}

// SMTP SERVER --------------------------------------------------------------------------------------------------------------
// our access token retrieved from the OAUth 2.0 Playground expires after 4500 seconds, so we need to refresh
// the token in order to make OAuth2 generate a new secret code
const createTransport = async () => {
    // the oauth client requires (client ID, client Secret token and the oauth playground URL)
    // the oauth playground URL allows oauth to dynamically receive tokens from the refresh token
    const oauth2Client = new OAuth2(
        process.env.CLIENT_ID,
        process.env.CLIENT_SECRET,
        "https://developers.google.com/oauthplayground"
    )

    // sets refresh token credentials to the OAuth2 Client
    // if the token is expired, the refresh token will auto generate a new access token
    oauth2Client.setCredentials({
        refresh_token: process.env.REFRESH_TOKEN
    });


    // this function gets the access token from the OAuth2 Client
    const accessToken = await new Promise((resolve, reject) => {
        oauth2Client.getAccessToken((err, token) => {
            if (err) {
                reject("Failed to create access token:(");
            }
            resolve(token);
        })
    });

    // the transporter object contains configuration details which will be used when sending the email
    // using OAuth2 API configuration means we won't need to store the password of the Gmail account
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            type: 'OAuth2',
            user: process.env.EMAIL,
            accessToken,
            clientId: process.env.CLIENT_ID,
            clientSecret: process.env.CLIENT_SECRET,
            refreshToken: process.env.REFRESH_TOKEN
        },
        // rejects unauthorised clients
        tls: {
            rejectUnauthorized: false
        }
    })
    return transporter;
}

// otp generator ------------------------------------------------------------------------------------------------------

let otp = Math.random();
otp = otp * 1000000;
otp = parseInt(otp);
//console.log(otp);

// -----------------------------------------------------------------

app.get('/login', loginLimiter, csrfProtection, (req, res) => {
    if (req.session.loggedin) {
        res.redirect('/login', { csrfToken: req.csrfToken() });
    } else {
        //console.log(req.csrfToken());
        res.render('login.ejs', { verified: req.session.loggedin, csrfToken: req.csrfToken() });
    }
});

app.post('/auth', parseForm, csrfProtection, (request, response) => {
    ////console.log("yikes")
    let username = request.body.username;
    let password = request.body.password;

    //dumb implementation of sanitization, uses regex(alphanumeric values only)
    function containsSpecialChars(username) {
        const specialChars = /[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/;
        return specialChars.test(str);
    }

    if(containsSpecialChars==true){
        return response.send('No special characters in input please!');
    }

    //'SELECT * FROM users where username==?', [req.body.registerusername],
    //"SELECT salt, password, lastlog FROM users where username==\"" + username + "\""
    //getData("SELECT salt, password, lastlog FROM users where username==?",[username]).then(results => {
    db.all(
        "SELECT salt, password, lastlog, userid,username, email FROM users where username==?", [username],
        (error, results) => {

            if (results !== undefined) {
                //console.log("password: ", results[0].password)
                //console.log("salt: ", results[0].salt)
                //console.log("lastlog: ", results[0].lastlog)

                //Check if last login is more than a month ago
                let timeDiff = Date.now() - new Date(results[0].lastlog);
                let timeDiffFormatted = timeDiff / (1000 * 60 * 60 * 24);
                //console.log(timeDiffFormatted);
                if (timeDiffFormatted < 30) {
                    bcrypt.hash(request.body.password, results[0].salt, function (err, hash) {
                        if (results[0].password == hash) {
                           //console.log("waiting")
                           //account enumeration by adding random time
                            let sleep = ms => new Promise(resolve => setTimeout(resolve, Math.random() * 1000));
                            //console.log("finished")
                            request.session.loggedin = true;
                            request.session.username = username;
                            //console.log('Success!')
                            //Regenerates session id on successful login
                            request.session.regenerate(function (err) {
                                if (err) {
                                    results(err);
                                }
                            });
                            db.run(
                                //'UPDATE users SET=? where username==?', VALUES(?, DATETIME('now'),? ,?)",
                                "UPDATE users SET lastlog=DATETIME('now') where username==\"" + username + "\"",
                                (error, results) => {
                                }
                            );

                            response.redirect('/');
                        } else {
                            //account enumeration by adding random time
                            let sleep = ms => new Promise(resolve => setTimeout(resolve, Math.random() * 1000));
                            response.send('Incorrect password or username');
                        }

                    });
                }
                else {
                    //Generate OTP
                    let otp = Math.random();
                    otp = otp * 1000000;
                    otp = parseInt(otp);
                    
                    console.log(otp);

                    //Update the user object with the new OTP
                    db.run(
                        "UPDATE users SET otp=\"" + otp + "\"where userid=\"" + results[0].userid + "\"",
                        (error, results) => {
                            //console.log(results)
                            //console.log(error)
                        })
                    response.render('otp.ejs', { csrfToken: request.csrfToken(), username: results[0].username, password: results[0].password });
                    // automatically sends email with otp code to email account
                    const sendEmail = async (mailOptions) => {
                        let newTransporter = await createTransport();
                        await newTransporter.sendMail(mailOptions);
                    }

                    // content of email
                    sendEmail({
                        // the content of the email
                        from: process.env.EMAIL,
                        // receiving email address
                        to: results[0].email,
                        subject: 'Your 2 factor authentication code',
                        // where the 6 digit code will be sent
                        html: "<h3>OTP for account verification is </h3>" + "<h1 style='font-weight:bold;'>" + otp + "</h1>" 
                        + "<h5> Please note: We will never ask for your login details nor 2 factor authentication codes from you.</h5>",

                    })
                }
                // check to see how long the user hasn't logged in from
                // if user hasn't logged in for a month, send email
                // let checkIfUserLoggedIn = currentDateTime - results.


                //response.status(301).redirect("https://google.com")
                //response.redirect('/account');


            } else {
                //Account enumeration mitigation lol
                response.send('Incorrect password or username');
            }
            //response.send('Incorrect username or password');
            // delay timer potentially put in here

        })
});

app.post('/otpAuth', parseForm, csrfProtection, (request, response) => {
    //console.log("yikes")
    let username = request.body.username;
    let password = request.body.password;
    let otp = request.body.otp;
    //console.log("TRANS: ", username)
    //console.log("TRANS: ", password)
    //console.log("OTP BLABALBALB: " + otp)

    query = "SELECT userid, otp FROM users where username==\"" + username + "\""
    //query = "SELECT userid, otp FROM users where username==\"" + username + "\"AND password==\"" + password + "\""
    getData(query).then(results => {
        if (results) {
            //console.log(results.userid)
            //console.log(results.otp)
            if (results.otp == otp) {
                request.session.loggedin = true;
                request.session.username = username;
                //console.log('Success!')
                db.run(
                    "UPDATE users SET lastlog=DATETIME('now') where username==\"" + username + "\"",
                    (error, results) => {
                    }
                );
                response.redirect('/');
            }
            ////console.log(results);
            else {
                response.send('Something went wrong. Please try logging in again.');
            }
        }

        //response.send('Incorrect username or password');
        // delay timer potentially put in here

    })
});


app.get('/logout', (req, res) => {
    req.session.loggedin = false;
    req.session.username = null;
    res.redirect('/');
});

app.get('/user', (req, res) => {
    if (req.session.loggedin) {
        res.send(req.session.username);
    } else {
        res.redirect('/login');
    }
});

// Index page
app.get('/', (req, res) => {
    db.run(
        'UPDATE users SET lastlog="2022-02-09 22:44:15" where username=="RobinEmail"',
        (error, results) => {
        }
    );
    const regexAlphaNumeric = /^[a-z0-9]+$/;

    db.all(
        'SELECT content, * FROM posts',
        (error, results) => {

            res.render('index.ejs', { posts: results, verified: req.session.loggedin, Truncate: truncate, username: req.session.username });
        }
    );
});

app.get('/createPost', (req, res) => {

    if (req.session.loggedin) {
        res.render('createPost.ejs', { verified: req.session.loggedin });
    } else {
        res.redirect('/login');
    }
});

app.post('/addpost', (req, res) => {
    db.all(
        "SELECT userid FROM users where username==\"" + req.session.username + "\"",
        (error, idresults) => {
            //var stripped = assign.replace(/\D/g, "");
            ////console.log(assign)
            db.all(
                "INSERT INTO posts(creator, date, title, content) VALUES(?, DATETIME('now'),? ,?)",
                [req.session.username, xss(req.body.title), xss(req.body.description)],
                (error, results) => {
                    res.redirect('/');
                }
            );
        }

    );
});

app.get('/account', (req, res) => {
    if (req.session.loggedin) {
        db.all(
            "SELECT userid FROM users where username==\"" + req.session.username + "\"",
            (error, idresults) => {
                db.all(
                    //"SELECT * FROM posts where creator==\"" + idresults[0].userid + "\"",
                    'SELECT * FROM posts where creator==?', [req.session.username],
                    (error, results) => {
                        res.render('account.ejs', { verified: req.session.loggedin, posts: results });
                    }
                );
            }
        );
    } else {
        res.redirect('/login');
    }
});


app.post('/editPost', (req, res) => {
    if (req.session.loggedin) {
        //console.log(req.body.postdetails)
        db.all(
            "SELECT userid FROM users where username==\"" + req.session.username + "\"",
            (error, idresults) => {
                db.all(
                    //"SELECT * FROM posts where creator==\"" + idresults[0].userid + "\" AND title== \"" + req.body.postdetails + "\"",
                    'SELECT * FROM posts where creator==? AND title==?', [req.session.username, req.body.postdetails],
                    (error, results) => {
                        let title = xss(results[0].title)
                        let content = xss(results[0].content)
                        res.render('editPost.ejs', { verified: req.session.loggedin, title: title, content: content });
                    }
                );
            }
        );
    } else {
        res.redirect('/login');
    }
});

app.post('/editPostsubmit', (req, res) => {
    if (req.session.loggedin) {
        db.all(
            "SELECT userid FROM users where username==\"" + req.session.username + "\"",
            (error, idresults) => {
                db.run(
                    //"UPDATE posts SET title=\"" + xss(req.body.title) + "\", content=\"" + xss(req.body.description) + "\" where creator==\"" + idresults[0].userid + "\" AND title==\"" + req.body.postdetails + "\"",
                    'UPDATE posts SET title=?, content=? where creator ==? and title==?', [xss(req.body.title), xss(req.body.description), req.session.username, req.body.postdetails],
                    (error, results) => {
                        ////console.log("new title: ", req.body.title)
                        ////console.log("new content: ",req.body.description)
                        ////console.log("original title: ",req.body.postdetails)
                        ////console.log(req.body)
                        ////console.log(results)
                        ////console.log(error)
                        res.redirect('/account');
                    }
                );
            }
        );
    } else {
        res.redirect('/login');
    }
});

app.post('/deletePost', (req, res) => {
    //console.log("in delete post")
    if (req.session.loggedin) {
        //console.log(req.body.postdetails)
        console.log(req.session.username)
        console.log(req.body.postdetails)
                db.run(
                    //"DELETE FROM posts where creator==\"" + req.session.username + "\" AND title== \"" + req.body.postdetails + "\"",
                    "DELETE FROM posts where creator==? AND title==?",[req.session.username,req.body.postdetails],
                    (error, results) => {
                        res.redirect('/account');
                    }
                );
            }
       
     else {
        res.redirect('/login');
    }
});

app.get('/register', (req, res) => {
    const fileNames = []
    //make random captcha code
    for (let i = 0; i < 6; i++) {
        var lol = Math.floor(Math.random() * 10)
        fileNames.push(path.join(lol + ".png"))
        captchaArray += String(lol);
        
    }
    console.log(captchaArray)
    app.use(express.static(path.join(__dirname, "0.png")))
    //{ verified: req.session.loggedin }
    res.render('register.ejs', { pic1: fileNames[0], pic2: fileNames[1], pic3: fileNames[2], pic4: fileNames[3], pic5: fileNames[4], pic6: fileNames[5] })

});




//"INSERT INTO posts(creator, date, title, content) VALUES(?, DATETIME('now'),? ,?)"
app.post('/registerauth', async function (req, res) {
    /*     //console.log(req.body.registerusername)
        //console.log(req.body.registerpassword)
        //console.log(req.body.registerpassword2)
        //console.log(req.body.registername)
        //console.log(req.body.registeremail) */
    //password is hash
    //salt is salt

    function containsSpecialChars(str) {
        const specialChars = /[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/;
        return specialChars.test(str);
    }

    db.all(
        //"SELECT * FROM users where username==\"" + req.body.registerusername + "\"",
        'SELECT * FROM users where username==?', [req.body.registerusername],
        (error, results) => {
            if (results.length > 0) {
                //console.log(results[0])
                res.send("username already exists broski")
            }
            else {
                if (req.body.registerpassword == req.body.registerpassword2) {
                    var checkboolean = false

                    for (let i = 0; i < req.body.registerpassword.length; i++) {
                        if (req.body.registerpassword[i] >= '0' && req.body.registerpassword[i] <= '9') {
                            checkboolean = true
                            //console.log("password contains number")
                        }
                    }

                    //console.log("specialcharacters: ", containsSpecialChars(req.body.registerpassword))
                    //console.log("checkboolean: ", checkboolean)
                    //console.log("password length: ", req.body.registerpassword.length)
                    if (req.body.registerpassword.length > 10 && containsSpecialChars(req.body.registerpassword) && checkboolean == true) {
                        //console.log(captchaArray)
                        //console.log(req.body.captcha)
                        if (req.body.captcha == captchaArray) {
                            //console.log("success")
                            bcrypt.genSalt(saltRounds, function (err, salt) {
                                //saltedpassword = salt + req.body.registerpassword
                                //console.log('salt: ' + salt)

                                ////console.log(saltedpassword)
                                bcrypt.hash(req.body.registerpassword, salt, function (err, hash) {
                                    //console.log("hash: ", hash)
                                    db.run(
                                        "INSERT INTO users(username, name, password, email, salt, lastlog, otp) VALUES(?,?,?,?,?, DATETIME('now'),?)",
                                        [req.body.registerusername, req.body.registername, hash, req.body.registeremail, salt, '111111'],
                                        (error, results) => {
                                            res.redirect('/login');
                                        }
                                    );
                                });
                            });
                        }
                        else {

                            res.send('Incorrect captcha');
                        }
                    }
                    else {
                        console.log(req.body.registerpassword)
                        console.log(req.body.registerpassword2)
                        res.send('Insecure password');
                    }
                }
                else {
                    res.send('password fields arent the same');
                }
                captchaArray = '';
            }
        }
    );
});

app.post('/search', async function (req, res) {
    ////console.log(req.body.searchterm)
    //res.redirect('/searched');
    db.all(
        'SELECT * FROM posts WHERE title like ?', [req.body.searchterm],
        (error, results) => {
            //console.log(results.length)
            res.render('index.ejs', { posts: results, verified: req.session.loggedin, Truncate: truncate, username: req.session.username });
        }
    );
});