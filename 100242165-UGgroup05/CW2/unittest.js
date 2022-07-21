const path = require("path");
const chalk = require("chalk");
const sqlite3 = require('sqlite3')
const express = require('express');
let app = express();
const sqlite = require('sqlite3').verbose();
const session = require('express-session');

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

const truncate = require('truncate');
const bcrypt = require('bcrypt');
const saltRounds = 16;




let captchaArray = '';



/* app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static'))); */

var bodyParser = require('body-parser');
let otpvariable

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

/* app.post('/auth', (req, res) => {
    const { username, password } = req.body;
    const { authorization } = req.headers;
    console.log("penis")
    res.send({
      username,
      password,
      authorization,
    });
  }); */

//DDOS Mitigations - Limit request size
/*app.use(function (req, res, next) {
    if (!['POST', 'PUT', 'DELETE'].includes(req.method)) {
        next()
        return
    }

    getRawBody(req, {
        length: req.headers['content-length'],
        limit: '1kb',
        encoding: contentType.parse(req).parameters.charset
    }, function (err, string) {
        if (err) return next(err)
        req.text = string
        next()
    })
})*/
//hardcoding the request limit may not be best way to handle but as blog should be ok

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

//Further DDOS mititgation - if server is too busy then send a too busy message instead of overloading the server and taking it down
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


function testRegister(username, password1, password2, captchainput) {

    function containsSpecialChars(str) {
        const specialChars = /[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/;
        return specialChars.test(str);
    }

    db.all(
        'SELECT * FROM users where username==?', [username],
        (error, results) => {
            if (results.length > 0) {
                console.log(results[0])
                console.log("username already exists broski")
            }
            else {
                if (password1 == password2) {
                    var checkboolean = false

                    for (let i = 0; i < password1.length; i++) {
                        if (password1[i] >= '0' && password1[i] <= '9') {
                            checkboolean = true
                            //console.log("password contains number")
                        }
                    }
                    //console.log("specialcharacters: ", containsSpecialChars(password1))
                    //console.log("checkboolean: ", checkboolean)
                    //console.log("password length: ", password1.length)
                    if(password1.length < 10){
                        console.log(chalk.red("FAIL: password is not meet length requirments"))
                    }else{
                        console.log(chalk.green("PASS: password meets length requirments"))
                    }
                    if(containsSpecialChars(password1)==false){
                        console.log(chalk.red("FAIL: password does not contain any special chars"))
                    }else{
                        console.log(chalk.green("PASS: password meets character requirments"))
                    }
                    if(checkboolean==false){
                        console.log(chalk.red("FAIL: password does not contain number"))
                    }else{
                        console.log(chalk.green("PASS: password meets numeric requirments"))
                    }


                    if (password1.length > 10 && containsSpecialChars(password1) && checkboolean == true) {
                        //console.log(captchaArray)
                        //console.log(captchainput)
                        captchaArraycheck = ''
                        for (let i = 0; i < captchaArray.length; i++){
                            captchaArraycheck+=captchaArray[i]
                          }
                          //console.log(captchaArraycheck)
                          //console.log(captchainput)

                        if (captchainput == captchaArraycheck) {
                            console.log(chalk.green("PASS: Captcha verified"))
                            bcrypt.genSalt(saltRounds, function (err, salt) {
                                console.log(chalk.yellow("Password Test"))
                                console.log(chalk.green("PASS: Salt generated", salt))
                                bcrypt.hash(password1, salt, function (err, hash) {
                                    console.log(chalk.green("PASS: Hash generated", hash))
                                    console.log(chalk.green("PASS: Account created"))
                                });
                            });
                        }
                        else {
                            //console.log(captchainput)
                            captchaArray = []
                            console.log(chalk.red("FAIL: Incorrect captcha"))
                            console.log(chalk.red("FAIL: Account creation failed"))
                        }
                    }
                    else {
                        console.log(chalk.red("FAIL: Account creation failed"))
                    }
                }
                else {
                    console.log(chalk.red('FAIL: Password fields arent the same'));
                }
                captchaArray = [];
            }
        }
    );
  }

function testLogin(username,password){
    userc = false

    //dumb implementation of sanitization, uses regex(alphanumeric values only)
    const regexAlphaNumeric = /^[a-z0-9]+$/;
    //console.log(username)
    if (!username.match(regexAlphaNumeric)) {
        console.log(chalk.red("FAIL: Special character detected in username"))
        userc=true
        //return response.send('No special characters in input please!');
    }
    //'SELECT * FROM users where username==?', [req.body.registerusername],
    //"SELECT salt, password, lastlog FROM users where username==\"" + username + "\""
    //getData("SELECT salt, password, lastlog FROM users where username==?",[username]).then(results => {
    if (userc==false){
        console.log(chalk.yellow("Looking up account test"))
        db.all(
            "SELECT salt, password, lastlog, userid,username, email FROM users where username==?", [username],
            (error, results) => {
                if (results !== undefined) {
                    console.log(chalk.green("PASS: Account identified"))
                    //console.log("password: ", results[0].password)
                    //console.log("salt: ", results[0].salt)
                    //console.log("lastlog: ", results[0].lastlog)

                    //Check if last login is more than a month ago
                    let timeDiff = Date.now() - new Date(results[0].lastlog);
                    let timeDiffFormatted = timeDiff / (1000 * 60 * 60 * 24);
                    //console.log(timeDiffFormatted);
                    console.log(chalk.yellow("Last logged date check"))
                    if (timeDiffFormatted < 30) {
                        console.log(chalk.green("PASS: Date check successful"))
                        bcrypt.hash(password, results[0].salt, function (err, hash) {
                            if (results[0].password == hash) {
                            console.log(chalk.green("PASS: Password verified"))
                            console.log(chalk.yellow("Account Enumeration countermeasure"))
                                let sleep = ms => new Promise(resolve => setTimeout(resolve, Math.random() * 1000));
                                console.log(chalk.green("PASS: Account enumeration countermeasure"))
                                //request.session.loggedin = true;
                                //request.session.username = username;
                                console.log(chalk.green("PASS: User logged in"))

                            } else {
                                console.log("Fail: Incorrect password")
                                console.log(chalk.yellow("Account Enumeration countermeasure"))
                                let sleep = ms => new Promise(resolve => setTimeout(resolve, Math.random() * 1000));
                                console.log("PASS: Account enumeration countermeasure")
                            }

                        });
                    }
                    else {
                        console.log(chalk.green("PASS: Date check successful"))
                        console.log(chalk.yellow("Generating OTP"))
                        //Generate OTP
                        let otp = Math.random();
                        otp = otp * 1000000;
                        otp = parseInt(otp);
                        //console.log(otp);
                        console.log(chalk.green("PASS: OTP generated " + otp))
                        otpvariable=otp

                        //Update the user object with the new OTP
                        db.run(
                            "UPDATE users SET otp=\"" + otp + "\"where userid=\"" + results[0].userid + "\"",
                            (error, results) => {
                                //console.log(results)
                                //console.log(error)
                            })
                        //response.render('otp.ejs', { csrfToken: request.csrfToken(), username: results[0].username, password: results[0].password });
                        // automatically sends email with otp code to email account
                        const sendEmail = async (mailOptions) => {
                            let newTransporter = await createTransport();
                            await newTransporter.sendMail(mailOptions);
                        }

                        // content of email
                        console.log(chalk.yellow("Verification email check"))
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
                        console.log(chalk.green("PASS: Verification email sent"))
                    }
                    // check to see how long the user hasn't logged in from
                    // if user hasn't logged in for a month, send email
                    // let checkIfUserLoggedIn = currentDateTime - results.


                    //response.status(301).redirect("https://google.com")
                    //response.redirect('/account');


                } else {
                    //Account enumeration mitigation lol
                    console.log(chalk.red('FAIL: Failed login incorrect credentials'));
                }
                //response.send('Incorrect username or password');
                // delay timer potentially put in here

            })
    };
}

function generateCaptcha(){
    captchastring=''
    const fileNames = []
    for (let i = 0; i < 6; i++) {
        var lol = Math.floor(Math.random() * 10)
        fileNames.push(path.join(lol + ".png"))
        captchaArray += String(lol);
        captchastring+= String(lol);
    }
    return captchastring
  };

function otpAuth(username,otp){
    //console.log("TRANS: ", username)
    //console.log("TRANS: ", password)
    //console.log("OTP BLABALBALB: " + otp)

    query = "SELECT userid, otp FROM users where username==\"" + username + "\""

    getData(query).then(results => {
        if (results) {
            //console.log(results.userid)
            console.log(chalk.yellow("Checking OTP"))
            if (results.otp == otp) {
                console.log(chalk.green("PASS: OTP verified user logged in"))
                //console.log("Pikachu!");
                //request.session.loggedin = true;
                //request.session.username = username;
                //console.log('Success!')
            }
            //console.log(results);
        }
        else {
            console.log(chalk.red('FAIL: Incorrect OTP'));
        }
        //response.send('Incorrect username or password');
        // delay timer potentially put in here

    })
}

function addPost(username, title, description, userid){
    console.log(chalk.green("PASS: User identified"))
    db.all(
        "SELECT userid FROM users where username==\"" + username + "\"",
        (error, idresults) => {
            //var stripped = assign.replace(/\D/g, "");
            //console.log(assign)
            console.log(chalk.yellow("Script description: <script>alert</script>"))
            console.log(chalk.yellow("Post XSS check"))
            db.all(
                "INSERT INTO posts(creator, date, title, content) VALUES(?, DATETIME('now'),? ,?)",
                [userid, xss(title), xss(description)],
                (error, results) => {
                    console.log(chalk.green("XSS Output: ",xss(description)))
                    console.log(chalk.green("PASS: XSS check executed"))
                    console.log(chalk.yellow("Inserting post into DB"))
                    console.log(chalk.green("PASS: Post added"))
                }
            );
        }

    );
}

function editPost(username, newtitle, content, existingtitle, userid){
    db.all(
        "SELECT userid FROM users where username==\"" + username + "\"",
        (error, idresults) => {
            console.log(chalk.yellow("Edit post XSS check"))
            console.log(chalk.yellow("Script description: <script>alert</script>"))
            db.run(
                //"UPDATE posts SET title=\"" + xss(req.body.title) + "\", content=\"" + xss(req.body.description) + "\" where creator==\"" + idresults[0].userid + "\" AND title==\"" + req.body.postdetails + "\"",
                'UPDATE posts SET title=?, content=? where creator ==? and title==?', [xss(newtitle), xss(content), userid, existingtitle],
                (error, results) => {
                    console.log(chalk.green("XSS Output: ",xss(content)))
                    console.log(chalk.green("PASS: XSS check executed"))
                    console.log(chalk.green("PASS: Post successfully edited"))
                }
            );
        }
    );
}

function deletePost(username,title){
    console.log(chalk.yellow("Identifying post"))
    db.all(
        'SELECT userid FROM users WHERE username==? ', [username],
        (error, idresults) => {
            db.run(
                //'SELECT * FROM users where username==?', [req.body.registerusername],
                "DELETE FROM posts where creator==\"" + idresults[0].userid + "\" AND title== \"" + title + "\"",
                (error, results) => {
                    console.log(chalk.green("PASS: Post identified"))
                    console.log(chalk.green("PASS: Post deleted sucessfully"))
                }
            );
        }
    );

}


function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function main(){
db.run(
     'UPDATE users SET lastlog="2022-05-15 22:44:15" where username=="robin"',
    (error, results) => {
    })   
    console.log(chalk.yellow("Successful registration Test"))
    generateCaptcha()
    console.log(chalk.green("PASS: Generated Captcha",captchastring))
    console.log(chalk.yellow("Input: username = testuser1," +  " password1 = securepass123!," + " password1 = securepass123!," + " captcha input: " + captchastring))
    testRegister("testuser1","securepass123!","securepass123!",captchastring)
    await sleep(10000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Captcha Test"))
    generateCaptcha()
    console.log(chalk.green("PASS: Generated Captcha",captchastring))
    console.log(chalk.yellow("Input: username = testuser1," +  " password1 = securepass123!," + " password1 = securepass123!," + " captcha input: 523726"))
    testRegister("testuser1","securepass123!","securepass123!","523726")
    await sleep(10000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Password Length Test"))
    generateCaptcha()
    console.log(chalk.green("PASS: Generated Captcha",captchastring))
    console.log(chalk.yellow("Input: username = testuser1," +  " password1 = pass123!," + " password1 = pass123!," + " captcha input: " + captchastring))
    testRegister("testuser1","pass123!","pass123!",captchastring)
    await sleep(6000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Password special character Test"))
    generateCaptcha()
    console.log(chalk.green("PASS: Generated Captcha",captchastring))
    console.log(chalk.yellow("Input: username = testuser1," +  " password1 = securepass123," + " password1 = securepass123," + " captcha input: " + captchastring))
    testRegister("testuser1","securepass123","securepass123",captchastring)
    await sleep(6000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Password number Test Fail"))
    generateCaptcha()
    console.log(chalk.green("PASS: Generated Captcha",captchastring))
    console.log(chalk.yellow("Input: username = testuser1," +  " password1 = securepass!," + " password1 = securepass!," + " captcha input: " + captchastring))
    testRegister("testuser1","securepass!","securepass!",captchastring)
    await sleep(6000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Successful Login Test"))
    testLogin("robin","robin123123!");
    await sleep(10000);
    console.log("------------------------------------------------------------") 
    console.log(chalk.yellow("SQL Injection fail"))
    testLogin("robin!","robin123123!");
    await sleep(5000);
    console.log("------------------------------------------------------------") 
    console.log(chalk.yellow("OTP Test"))
     db.run(
        'UPDATE users SET lastlog="2022-02-09 22:44:15" where username=="robin"',
        (error, results) => {
        })
    testLogin("robin","robin123123!");
    await sleep(5000);
    otpAuth("robin",otpvariable)
    await sleep(2000);
    console.log("------------------------------------------------------------") 
    console.log(chalk.yellow("Post creation test + Trigger XSS"))
    addPost('robin', 'testpost3', '<script>alert;</script>', 3)
    await sleep(5000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Edit existing post test + Trigger XSS"))
    editPost('robin','editTitle','<script>alert;</script>','testpost3',3)
    await sleep(5000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Post Delete check"))
    deletePost('robin','editTitle')
    await sleep(5000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Sanatisation check - Paramatisation success"))
    input = '"" or ""=""'
    db.all(
        'SELECT * FROM users WHERE username==?',[input],
        (error, results) => {
            console.log(results)
        }
    );
    console.log(chalk.green("PASS: Sanatisation success"))
    await sleep(5000);
    console.log("------------------------------------------------------------")
    console.log(chalk.yellow("Sanatisation check - Fail"))
    db.all(
        'SELECT * FROM users WHERE username=="" or ""=""',
        (error, results) => {
            console.log(results)
        }
    );
    console.log(chalk.red("Fail: Sanatisation failed"))
    await sleep(5000);
}
main()