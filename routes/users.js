const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const passport = require('passport');

//Login page
router.get('/login', (req, res) => {
	res.render('login');
});

//Register
router.get('/register', (req, res) => {
	res.render('register');
});

//register handler
router.post('/register', (req, res) => {
	const { name, email, password, password2 } = req.body;
	let errors = [];

	//Check required
	if (!name || !email || !password || !password2) {
		errors.push({ msg: 'Please fill in all fields' });
	}

	//Check pass match
	if (password !== password2) {
		errors.push({ msg: 'Passwords do not match' });
	}

	//Check pass length
	if (password.length < 6) {
		errors.push({ msg: 'Password should be at least 6 characters' });
	}

	if (errors.length > 0) {
		res.render('register', {
			errors,
			name,
			email,
			password,
			password2
		});
	} else {
		User.findOne({ email: email })
			.then(user => {
				if (user) {
					//user exists and rerenders with the same fields as before
					errors.push({ msg: 'Email is already in use' });
					res.render('register', {
						errors,
						name,
						email,
						password,
						password2
					});

				} else {
					const newUser = new User({
						name,
						email,
						password
					});

					//Hash pass
					bcrypt.genSalt(10, (err, salt) =>
						bcrypt.hash(newUser.password, salt, (err, hash) => {
							if (err) throw err;
							//set pass to hash
							newUser.password = hash;
							//save user to mongo
							newUser.save()
								.then(() => {
									req.flash('success_msg', 'You are now registered and can log in');
									res.redirect('/users/login');
								})
								.catch();
						}));
				}
			});
	}
});

//Login handler
router.post('/login', (req, res, next) => {
	passport.authenticate('local', {
		successRedirect: '/dashboard',
		failureRedirect: '/users/login',
		failureFlash: true
	})(req, res, next);
});

//Logout handler

router.get('/logout', (req, res) => {
	req.logout();
	req.flash('success_msg', 'You logged out');
	res.redirect('/users/login');
});

module.exports = router;