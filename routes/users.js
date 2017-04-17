var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');

// Register
router.get('/rejestr', function(req, res){
	res.render('rejestr');
});

// Login
router.get('/login', function(req, res){
	res.render('login');
});

// Register User
router.post('/rejestr', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	// sprawdzenie danych
	req.checkBody('name', 'Imie jest wymagane').notEmpty();
	req.checkBody('email', 'Email jest wymagany').notEmpty();
	req.checkBody('email', 'Email jest już zajęty!').isEmail();
	req.checkBody('username', 'Porsze podać nazwe').notEmpty();
	req.checkBody('password', 'Hasło jest wymagane').notEmpty();
	req.checkBody('password2', 'Hasło nie pasuje!').equals(req.body.password);

	var errors = req.validationErrors();

	if(errors){
		res.render('rejestr',{
			errors:errors
		});
	} else {
		var newUser = new User({
			name: name,
			email:email,
			username: username,
			password: password
		});

		User.createUser(newUser, function(err, user){
			if(err) throw err;
			console.log(user);
		});

		req.flash('success_msg', 'Rejestracja zakończona pomyślnie można się zalogować');

		res.redirect('/users/login');
	}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
   User.getUserByUsername(username, function(err, user){
   	if(err) throw err;
   	if(!user){
   		return done(null, false, {message: 'Nieznany Użytkownik!'});
   	}

   	User.comparePassword(password, user.password, function(err, isMatch){
   		if(err) throw err;
   		if(isMatch){
   			return done(null, user);
   		} else {
   			return done(null, false, {message: 'Niepoprawne hasło!'});
   		}
   	});
   });
  }));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'Jesteś wylogowany/a');

	res.redirect('/users/login');
});

module.exports = router;
