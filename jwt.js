var jwt = require('jsonwebtoken');

module.exports = function () {
	var seneca = this;
	var plugin = 'jwt';

	seneca.add({role: plugin, cmd: 'sign'}, sign);
	seneca.add({role: plugin, cmd: 'verify'}, verify);
	seneca.add({role: plugin, cmd: 'decode'}, decode);

	function sign(msg, done) {
		var token;

		if (Buffer.isBuffer(msg.secret)) {
			token = jwt.sign(msg.payload, msg.secret, {noTimestamp: true, algorithm: msg.algorithm});
		} else {
			token = jwt.sign(msg.payload, msg.secret, {noTimestamp: true});
		}

		done(null, {token: token});
	}

	function verify(msg, done) {
		var decoded;

		if (Buffer.isBuffer(msg.secret)) {
			decoded = jwt.verify(msg.token, msg.secret, {noTimestamp: true});
		} else {
			decoded = jwt.verify(msg.token, msg.secret, {noTimestamp: true});
		}

		done(null, decoded);
	}

	function decode(msg, done) {
		var decoded = jwt.decode(msg.token);
		done(null, decoded);
	}
};
