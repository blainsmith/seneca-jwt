var path = require('path');
var fs = require('fs');
var test = require('tape');
var seneca = require('seneca')();
seneca.use('..');

var payload = {
	name: 'Blain Smith',
	email: 'rebelgeek@blainsmith.com',
	github: 'blainsmith'
};

var secret = 'shhhhh';
var hs256token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiQmxhaW4gU21pdGgiLCJlbWFpbCI6InJlYmVsZ2Vla0BibGFpbnNtaXRoLmNvbSIsImdpdGh1YiI6ImJsYWluc21pdGgifQ.AklQQAaB8EF4ryY35mL87hXRoPiM5O3ShiSAYES-RZo';

var privateKey = fs.readFileSync(path.join(__dirname, '/keys/jwt'));
var publicKey = fs.readFileSync(path.join(__dirname, '/keys/jwt.pub'));
var rs256token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiQmxhaW4gU21pdGgiLCJlbWFpbCI6InJlYmVsZ2Vla0BibGFpbnNtaXRoLmNvbSIsImdpdGh1YiI6ImJsYWluc21pdGgifQ.Mj6OOD4ObDlefdgO0Raw-Y7fzoAuy6ag4p9_CcIA1FUwcYJCWoAXBPJSQIU5nRC6WGK934-i83Un7TO9s3XkubvH4ztta1uoIpv56kRHP9aZhIVZqLmMXNOGakzxt2lpbXpoFUUsSbEUyDzg3wTf2dcH88dv87QzCL28YPCdjcUHQyvjQ11mU-A3DolW1llSE_n_QjRks6alDkis88MmRh6Rj8YnNTo629wBlOeNUM-OgaQJWwro817SDPc5x36g65fBkoxoJIgBnZSpPRDy4fVNT3_uifSYmh9z4LB_lDIFl_U-pl0H-tfU1N1kt5jLOn69DIYg0hyjpnkwU5H8LQ';

test('Secret String', function (t) {
	t.plan(3);

	seneca.act({role: 'jwt', cmd: 'sign', payload: payload, secret: secret}, function (errSign, resultSign) {
		t.equal(resultSign.token, hs256token, 'signing yields correct token');

		seneca.act({role: 'jwt', cmd: 'verify', token: resultSign.token, secret: secret}, function (errVerify, resultVerify) {
			t.deepEqual(resultVerify, payload, 'verifying yields the correct payload');

			seneca.act({role: 'jwt', cmd: 'decode', token: resultSign.token}, function (errDecode, resultDecode) {
				t.deepEqual(resultDecode, payload, 'decoding yields the correct payload');
			});
		});
	});
});

test('Public/Private Keys', function (t) {
	t.plan(3);

	seneca.act({role: 'jwt', cmd: 'sign', payload: payload, secret: privateKey, algorithm: 'RS256'}, function (errSign, resultSign) {
		t.equal(resultSign.token, rs256token, 'signing yields correct token');

		seneca.act({role: 'jwt', cmd: 'verify', token: resultSign.token, secret: publicKey}, function (errVerify, resultVerify) {
			t.deepEqual(resultVerify, payload, 'verifying yields the correct payload');

			seneca.act({role: 'jwt', cmd: 'decode', token: resultSign.token}, function (errDecode, resultDecode) {
				t.deepEqual(resultDecode, payload, 'decoding yields the correct payload');
			});
		});
	});
});
