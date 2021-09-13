const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const { ExtractJwt } = require("passport-jwt");
const { JWT_SECRET, auth } = require("../configs");
const LocalStrategy = require("passport-local").Strategy;
const GooglePlusTokenStrategy = require("passport-google-plus-token");
const FacebookTokenStrategy = require("passport-facebook-token");
const User = require("../models/User");

// Passport JWT
passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken("Authorization"),
      secretOrKey: JWT_SECRET,
    },
    async (payload, done) => {
      try {
        const user = await User.findById(payload.sub);

        if (!user) return done(null, false);

        done(null, user);
      } catch (error) {
        done(error, false);
      }
    }
  )
);

// Passport Google Plus
passport.use(
  new GooglePlusTokenStrategy(
    {
      clientID: auth.google.CLIENT_ID,
      clientSecret: auth.google.CLIENT_SECRET,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log("accessToken", accessToken);
        console.log("refreshToken", refreshToken);
        console.log("profile", profile);
        // Check whether this current user exists in our database
        const user = await User.findOne({
          authGoogleID: profile.id,
          authType: "google",
        });

        if (user) return done(null, user);

        // If new account
        const newUser = new User({
          authGoogleID: profile.id,
          authType: "google",
          email: profile.emails[0].value,
          firstName: profile.name.givenName,
          lastName: profile.name.familyName,
        });

        await newUser.save();

        done(null, newUser);
      } catch (error) {
        done(error, false);
      }
    }
  )
);

// Passport Facebook
passport.use(
  new FacebookTokenStrategy(
    {
      clientID: auth.facebook.CLIENT_ID,
      clientSecret: auth.facebook.CLIENT_SECRET,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check whether this current user exists in our database
        const user = await User.findOne({
          authFacebookID: profile.id,
          authType: "facebook",
        });

        if (user) return done(null, user);

        // If new account
        const newUser = new User({
          authGoogleID: profile.id,
          authType: "facebook",
          email: profile.emails[0].value,
          firstName: profile.name.givenName,
          lastName: profile.name.familyName,
        });

        await newUser.save();

        done(null, newUser);
      } catch (error) {
        done(error, false);
      }
    }
  )
);

// Passport local
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
    },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });

        if (!user) return done(null, false);

        const isCorrectPassword = await user.isValidPassword(password);

        if (!isCorrectPassword) return done(null, false);

        done(null, user);
      } catch (error) {
        done(error, false);
      }
    }
  )
);
