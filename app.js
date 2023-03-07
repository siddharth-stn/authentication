const express = require("express");
const bcrypt = require("bcryptjs");

const PORT = 3000;

// require the libraries installed for authentication
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const mongoose = require("mongoose");
const Schema = mongoose.Schema;

mongoose.set("strictQuery", false);

const mongoDbURL =
  "mongodb+srv://siddharth:hanumanji@express-mongo.dlhwrs5.mongodb.net/authentication?retryWrites=true&w=majority";

main().catch((err) => console.err(err));
async function main() {
  await mongoose.connect(mongoDbURL);
}

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const app = express();

app.set("views", __dirname);
app.set("view engine", "pug");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username })
      .then((user) => {
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect Password" });
          }
        });
      })
      .catch((err) => {
        return done(err);
      });
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => done(err));
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.locals.currUser = req.user;
  next();
});

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", (req, res, next) => {
  bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
    if (err) {
      return next(err);
    }
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
    });

    user
      .save()
      .then((result) => {
        console.log("Data saved successfully");
        console.log(`Data is: ${result}`);
        res.redirect("/");
      })
      .catch((err) => next(err));
  });
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(PORT, () => {
  console.log("App is running...");
});
