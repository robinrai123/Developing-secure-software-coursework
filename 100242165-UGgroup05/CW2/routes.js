const express = require("express");

const router = express.Router();

router.get("/", function(req, res) {
    console.log("Loading homepage");
    res.render("index");
})

router.get("/login", function(req, res) {
    console.log('Loading Login screen');
    res.render("login")
})

router.get("/register", function(req, res) {
    console.log('Loading Registration screen');
    res.render("register")
})

router.get("/account", function(req, res) {
    console.log('Loading account screen');
    res.render("account")
})

router.get("/createPost", function(req, res) {
    console.log('Loading Create Post screen');
    res.render("createPost")
})

module.exports = router;