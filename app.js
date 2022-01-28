require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended : true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser : true});

const userSchema = new mongoose.Schema({
  email : String,
  password: String
});

const User = new mongoose.model("User", userSchema);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/logout", (req, res) => {
  res.redirect("/");
});

// Check if user login info exists in the database
app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username}, (err, foundUser) => {
    // if user doesn't exist in the DB, throw an error
    if (err) {
      console.log(err);
    // if user exists, verify password entered by the user to match the one in DB
    } else {
      if (foundUser) {
        // Compare the password the user entered with the hash that corresponds
        // with the password in the database
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if (result === true) {
            res.render("secrets");
          }
        });
      }
    }
  });
});

app.post("/register", (req, res) => {
  // Auto generate a salt and a hash
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {

    const newUser = new User({
      email : req.body.username,
      password : hash
    });

    newUser.save((err) => {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });
});

app.listen(3000, () => {
  console.log("Server started on port 3000.");
});
