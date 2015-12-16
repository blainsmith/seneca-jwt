var crypto = require('crypto');
var randomString = require('random-string');
var jwt = require('jsonwebtoken');

module.exports = function (options) {
	var seneca = this;
	var plugin = 'jwt';

	options = {
		key: options.key || null,
		privateKey: options.privateKey || null,
		publicKey: options.publicKey || null,
		algorithm: options.algorithm || 'RS256'
	};

	seneca.add({role: plugin, cmd: 'generateKey'}, generateKey);
	seneca.add({role: plugin, cmd: 'sign'}, sign);
	seneca.add({role: plugin, cmd: 'verify'}, verify);
	seneca.add({role: plugin, cmd: 'decode'}, decode);

	function generateKey(msg, done) {
		done(null, {key: crypto.createHash('sha512').update(randomString()).digest('base64')});
	}

	function sign(msg, done) {
		var key = msg.key || options.key || options.privateKey;
		var token;

		if (Buffer.isBuffer(key)) {
			token = jwt.sign(msg.payload, key, {noTimestamp: true, algorithm: msg.algorithm || options.algorithm});
		} else if (key) {
			token = jwt.sign(msg.payload, key, {noTimestamp: true});
		} else {
			return done(new Error('Unable to sign payload without a key'));
		}

		done(null, {token: token});
	}

	function verify(msg, done) {
		var key = msg.key || options.key || options.publicKey;

		jwt.verify(msg.token, key, {noTimestamp: true}, done);
	}

	function decode(msg, done) {
		var decoded = jwt.decode(msg.token);
		done(null, decoded);
	}

	return {
		name: plugin
	};
};
