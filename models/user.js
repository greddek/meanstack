var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');//for example "simple using of compare passowrd"

// creating new user that will be using schema type of base
var UserSchema = mongoose.Schema({
	username: {
		type: String,
		index:true
	},
	password: {
		type: String
	},
	email: {
		type: String
	},
	name: {
		type: String
	}
});
//export users from base
var User = module.exports = mongoose.model('User', UserSchema);
//creating user and hashing his password
module.exports.createUser = function(newUser, callback){
	bcrypt.genSalt(10, function(err, salt) {
	    bcrypt.hash(newUser.password, salt, function(err, hash) {
	        newUser.password = hash;
	        newUser.save(callback);
	    });
	});
}
//compare users name and if is true return one
module.exports.getUserByUsername = function(username, callback){
	var query = {username: username};
	User.findOne(query, callback);
}
//finding user by id(id is unique)
module.exports.getUserById = function(id, callback){
	User.findById(id, callback);
}
//compare password of user to login procedure
module.exports.comparePassword = function(candidatePassword, hash, callback){
	bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
    	if(err) throw err;
    	callback(null, isMatch);
	});
}
