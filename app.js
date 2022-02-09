require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook');
const RedditStrategy = require('passport-reddit').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const crypto = require('crypto');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended : true
}));

app.use(session({
  secret : process.env.SECRET,
  resave : false,
  saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser : true});

const userSchema = new mongoose.Schema({
  email : String,
  password: String,
  facebookId: String,
  googleId: String,
  redditId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err,user) => {
    done(err, user);
  });
});

// Try to authenticate users using their Google account
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Try to authenticate users using their Facebook account
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName']
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Try to authenticate users using their Reddit account
passport.use(new RedditStrategy({
    clientID: process.env.REDDIT_CONSUMER_KEY,
    clientSecret: process.env.REDDIT_CONSUMER_SECRET,
    callbackURL: "http://localhost:3000/auth/reddit/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    console.log(profile.id);

    User.findOrCreate({ redditId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/facebook",
  passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to Secrets page
    res.redirect("/secrets");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to Secrets page
    res.redirect("/secrets");
});

app.get("/auth/reddit", function(req, res, next){
  req.session.state = crypto.randomBytes(32).toString("hex");
  passport.authenticate("reddit", {
    state: req.session.state,
  })(req, res, next);
});

app.get("/auth/reddit/secrets", function(req, res, next){
  // Check for origin via state token
  if (req.query.state == req.session.state){
    passport.authenticate("reddit", {
      // Successful authentication, redirect to Secrets page
      successRedirect: "/secrets",
      failureRedirect: "/login"
    })(req, res, next);
  }
  else {
    next( new Error (403) );
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

// Display the secrets page if a cookie for the user's credentials
// is present when they enter localhost:3000/secrets
app.get("/secrets", (req, res) => {
  User.find({"secret": {$ne : null}}, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

// Log in an existing user and check if their credentials exist in the database
app.post("/login", (req, res) => {

  const user = new User ({
    username : req.body.username,
    password : req.body.password
  });

  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("secrets");
      });
    }
  });

});

// Register a new user
app.post("/register", (req, res) => {

    User.register({username: req.body.username}, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("secrets");
      });
    }
  });
});

// Store and save a secret that the user submitted
app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  console.log(req.user.id);

  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.listen(3000, () => {
  console.log("Server started on port 3000.");
});
