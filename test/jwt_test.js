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
var hs256token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiQmxhaW4gU21pdGgiLCJlbWFpbCI6InJlYmVsZ2Vla0BibGFpbnNtaXRoLmNvbSIsImdpdGh1YiI6ImJsYWluc21pdGgifQ.AklQQAaB8EF4ryY35mL87hXRoPiM5O3ShiSAYES-RZo';

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
	var rs256token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiQmxhaW4gU21pdGgiLCJlbWFpbCI6InJlYmVsZ2Vla0BibGFpbnNtaXRoLmNvbSIsImdpdGh1YiI6ImJsYWluc21pdGgifQ.Mj6OOD4ObDlefdgO0Raw-Y7fzoAuy6ag4p9_CcIA1FUwcYJCWoAXBPJSQIU5nRC6WGK934-i83Un7TO9s3XkubvH4ztta1uoIpv56kRHP9aZhIVZqLmMXNOGakzxt2lpbXpoFUUsSbEUyDzg3wTf2dcH88dv87QzCL28YPCdjcUHQyvjQ11mU-A3DolW1llSE_n_QjRks6alDkis88MmRh6Rj8YnNTo629wBlOeNUM-OgaQJWwro817SDPc5x36g65fBkoxoJIgBnZSpPRDy4fVNT3_uifSYmh9z4LB_lDIFl_U-pl0H-tfU1N1kt5jLOn69DIYg0hyjpnkwU5H8LQ';

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
