//Config file for Local Passport Strategy

// Add a refernece to the passport strategy
var LocalStrategy = require('passport-local').Strategy;

// Import the User Model
var User = require('../models/user.js');

module.exports = function(passport) {
	
	/**
	 * SETUP for session storage and retrieval
	 */
	
	//serialize user
	passport.serializeUser(function(user, done) {
		//done(middleware-function, input)
		done(null, user);
	});
	
	//deserialize user
	passport.deserializeUser(function(id, done) {
		User.findById(id, function(err, user) {
			done(err, user);
		});
	});
	
	//Login script
	passport.use('local-login', new LocalStrategy({
		passReqToCallback: true
	},
	function(req, username, password, done) {
		//Asynchronous process
		process.nextTick(function() {
			User.findOne({
				'username':username
			}, function(err, user) {
				//If error found
				if(err) {
					return done(err);
				}
				//No valid user found
				if (!user) {
					return done(null, false, req.flash('loginMessage', 'Incorrect Username'));
				}
				//No valid password found
				if (!user.validPassword(password)) {
					return done(null, false, req.flash('loginMessage', 'Incorrect Password'));
				}
				//If everything is okay - proceed with login
				return done(null, user);
			})
		})
	}));
	
};
