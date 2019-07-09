var passport = require('passport');
var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
var bcrypt = require('bcrypt');
var w_config = [];
const saltRound = 10;
/* GET home page. */
router.get('/', function(req, res, next) {
    console.log(req.user);
    console.log(req.isAuthenticated());
    res.render('home', { title: 'Home' });
});
router.get('/profile', authenticationMiddleware(),function (req, res) {
   res.render('profile', {title: 'Profile'});
});
router.get('/login',function (req, res) {
    res.render('login', {title: 'login'});
});
router.post('/login',function (req,res) {
   const db =  require('../db.js');
    const username = req.body.username;
    const password = req.body.password;
   db.query("SELECT * FROM users WHERE username = ?",[username], function(err, rows){
       if (!rows.length) {
           res.render('login', {title: 'login',error:'No user found.'});// req.flash is the way to set flashdata using connect-flash
       }else{
           if (!bcrypt.compareSync(""+password, rows[0].password.toString())){
               res.render('login', {title: 'login', error:'Oops! Wrong password.'});
           }else {
               req.login(rows[0].id, function (err) {
                   res.redirect('/');
               });
           }// if the user is found but the password is wrong
       }
   });
});
router.get('/logout',function (req, res) {
    req.logOut();
    res.redirect('/');
});
router.get('/register', function(req, res, next) {
  res.render('register', { title: 'Registration' });
});
router.post('/register', function(req, res, next) {
    req.checkBody('username','Username field cannot be empty').notEmpty();
    req.checkBody('username', 'Username must be between 4-15 characters long.').len(4, 15);
    req.checkBody('username', 'Username can only contain letters, numbers, or underscores.').matches(/^[A-Za-z0-9_-]+$/, 'i');
    req.checkBody('email', 'The email you entered is invalid, please try again.').isEmail();
    req.checkBody('email', 'Email address must be between 4-100 characters long, please try again.').len(4, 100);
    req.checkBody('password', 'Password must be between 8-100 characters long.').len(8, 100);
    req.checkBody("password", "Password must include one lowercase character, one uppercase character, a number, and a special character.").matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i");
    req.checkBody('passwordMatch', 'Password must be between 8-100 characters long.').len(8, 100);
    req.checkBody('passwordMatch', 'Passwords do not match, please try again.').equals(req.body.password);

    const  errors = req.validationErrors();
    if(errors){
        console.log(`errors: ${JSON.stringify(errors)}`);
    res.render('register', {title: 'Registration Error', errors: errors});


    }else {
        const username = req.body.username;
        const email = req.body.email;
        const password = req.body.password;

        const db = require('../db.js');
        bcrypt.hash(password,saltRound,function (err, hash) {
            db.query('INSERT INTO users (username, email, password) VALUE (?,?,?)',[username, email, hash], function (err, result, fields) {
                if(err)throw err;

                db.query('SELECT LAST_INSERT_ID() AS user_id', function (error , result, fields) {
                    if(error) throw error;

                    const user_id = result[0];

                    console.log(user_id);
                    req.login(user_id, function (err) {
                        res.redirect('/');
                    });
                });
                //res.render('index', { title: 'Registration Complete' });
            });
        });
    }

});
passport.serializeUser(function(user_id, done) {
    done(null, user_id);
});
passport.deserializeUser(function(user_id, done) {
        done(null, user_id);
});
function authenticationMiddleware () {
    return (req, res, next) => {
        console.log(`req.session.passport.user: ${JSON.stringify(req.session.passport)}`);

        if (req.isAuthenticated()) return next();
        res.redirect('/login')
    }
}

module.exports = router;
