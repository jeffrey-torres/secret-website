require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

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

// Encrypt secret message and password attribute of the user schema
userSchema.plugin(encrypt, { secret : process.env.SECRET, encryptedFields: ["password"]});

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
        // if password entered by the user matches the one in DB,
        // display the Secrets page
        if (foundUser.password === password) {
          res.render("secrets");
        }
      }
    }
  });

});

app.post("/register", (req, res) => {
  const newUser = new User({
    email : req.body.username,
    password : req.body.password
  });

  newUser.save((err) => {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets");
    }
  });
});



app.listen(3000, () => {
  console.log("Server started on port 3000.");
});
