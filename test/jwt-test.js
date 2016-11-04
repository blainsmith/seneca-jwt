var path = require('path');
var fs = require('fs');
var test = require('tape');
var seneca = require('seneca')(require('./config'));

seneca.use('..');

var payload = {
	name: 'Blain Smith',
	email: 'rebelgeek@blainsmith.com',
	github: 'blainsmith'
};

var hs256token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQmxhaW4gU21pdGgiLCJlbWFpbCI6InJlYmVsZ2Vla0BibGFpbnNtaXRoLmNvbSIsImdpdGh1YiI6ImJsYWluc21pdGgifQ.q44ynm7JKK7Ydprn4kei7lBY0J5V-aMO5ioZM6hxb1Q';

test('Generate a String Key', function (t) {
	t.plan(1);

	seneca.act({role: 'jwt', cmd: 'generateKey'}, function (errGenKey, resultGenKey) {
		t.ok(/^[a-zA-Z0-9+/]+={0,2}$/i.test(resultGenKey.key), 'generates a base64-encoded string');
		t.end(errGenKey);
	});
});

test('Secret String Key', function (t) {
	t.plan(3);

	var key = 'shhhhh';

	seneca.act({role: 'jwt', cmd: 'sign', payload: payload, key: key}, function (errSign, resultSign) {
		t.equal(resultSign.token, hs256token, 'signing yields correct token');

		seneca.act({role: 'jwt', cmd: 'verify', token: resultSign.token, key: key}, function (errVerify, resultVerify) {
			t.deepEqual(resultVerify, payload, 'verifying yields the correct payload');

			seneca.act({role: 'jwt', cmd: 'decode', token: resultSign.token}, function (errDecode, resultDecode) {
				t.deepEqual(resultDecode, payload, 'decoding yields the correct payload');
			});
		});
	});
});

test('Public/Private Keys', function (t) {
	t.plan(3);

	var privateKey = fs.readFileSync(path.join(__dirname, '/keys/jwt'));
	var publicKey = fs.readFileSync(path.join(__dirname, '/keys/jwt.pub'));
	var rs256token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQmxhaW4gU21pdGgiLCJlbWFpbCI6InJlYmVsZ2Vla0BibGFpbnNtaXRoLmNvbSIsImdpdGh1YiI6ImJsYWluc21pdGgifQ.bpaToQSWZLY5qsPsTG0tOREQO957wi_UaP8rrrhgQPh8yBV9uUYjoX4ciKNlwX3E3j8nfZ9jjiq8XVK6DWUl1vGlKFNFgAIuy5aVgC02jpvXHXA0g_Ygh2dCm5CL-GyK7zF5SoPXzQxEXAxO36ZPqPKZmlMYLahSzhR9Lik1ZAwTveARNNjKsYmGPAH7zQ-s55DeE19_om2acmki4RhVQpcdiXiiUsVz5dTgOIFYVQ0TEEz-49nSg4hdgmweoRbaqwoK3mdDbbw0uqDDBRLwrXRlvpC6SIKRSZhlhMf-va6zFUkttOB3IzmUjjYKv6gwZs-y5xmIUANEGgfF8Zzzcg';

	seneca.act({role: 'jwt', cmd: 'sign', payload: payload, key: privateKey, algorithm: 'RS256'}, function (errSign, resultSign) {
		t.equal(resultSign.token, rs256token, 'signing yields correct token');

		seneca.act({role: 'jwt', cmd: 'verify', token: resultSign.token, key: publicKey}, function (errVerify, resultVerify) {
			t.deepEqual(resultVerify, payload, 'verifying yields the correct payload');

			seneca.act({role: 'jwt', cmd: 'decode', token: resultSign.token}, function (errDecode, resultDecode) {
				t.deepEqual(resultDecode, payload, 'decoding yields the correct payload');
			});
		});
	});
});

test('Error Handling', function (t) {
	t.plan(4);

	seneca.act({role: 'jwt', cmd: 'sign', payload: payload}, function (errSign, resultSign) {
		t.notOk(resultSign, 'no result returned');
		t.equal(errSign.details.message, 'Unable to sign payload without a key', 'cannot sign without a key');

		seneca.act({role: 'jwt', cmd: 'verify', token: hs256token}, function (errVerify, resultVerify) {
			t.notOk(resultVerify, 'no result returned');
			t.equal(errVerify.details.message, 'secret or public key must be provided', 'cannot verify without a key');
		});
	});
});
