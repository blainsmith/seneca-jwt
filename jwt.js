var crypto = require('crypto');
var randomString = require('random-string');
var jwt = require('jsonwebtoken');

module.exports = function () {
	var seneca = this;
	var plugin = 'jwt';

	seneca.add({role: plugin, cmd: 'generateKey'}, generateKey);
	seneca.add({role: plugin, cmd: 'sign'}, sign);
	seneca.add({role: plugin, cmd: 'verify'}, verify);
	seneca.add({role: plugin, cmd: 'decode'}, decode);

	function generateKey(msg, done) {
		done(null, {key: crypto.createHash('sha512').update(randomString()).digest('base64')});
	}

	function sign(msg, done) {
		var token;

		if (Buffer.isBuffer(msg.key)) {
			token = jwt.sign(msg.payload, msg.key, {noTimestamp: true, algorithm: msg.algorithm});
		} else {
			token = jwt.sign(msg.payload, msg.key, {noTimestamp: true});
		}

		done(null, {token: token});
	}

	function verify(msg, done) {
		var decoded;

		if (Buffer.isBuffer(msg.key)) {
			decoded = jwt.verify(msg.token, msg.key, {noTimestamp: true});
		} else {
			decoded = jwt.verify(msg.token, msg.key, {noTimestamp: true});
		}

		done(null, decoded);
	}

	function decode(msg, done) {
		var decoded = jwt.decode(msg.token);
		done(null, decoded);
	}
};
