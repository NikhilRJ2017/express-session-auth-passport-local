const passport = require('passport');
const { validPassword } = require('../lib/passwordUtils');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;


const customFields = {
    usernameField: 'username',
    passwordField: 'password'
};

const verfiyCallback = (username, password, done) => {
    User.findOne({ username: username }).
        then((user) => {
            if (!user) {
                //*done(err(null if no err), 'user if user is found and vice-versa');
                return done(null, false);
            }

            const isValid = validPassword(password, user.hash, user.salt);

            if (isValid) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        }).
        catch((err) => {
            done(err);
        })
}

const strategy = new LocalStrategy(customFields, verfiyCallback);

passport.use(strategy);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((userId, done) => {
    User.findById(userId).
        then((user) => done(null, user)).
        catch((err) => done(err));
})
