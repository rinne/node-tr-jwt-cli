'use strict';

const jws = require('jws');
const jwtKeyParams = require('./data-jwt-key-params.js');
	  
function createJwt(algorithm, key, data) {
	var r;
	try {
		var sd = {
			header: { alg: algorithm, typ: 'JWT' },
			payload: JSON.stringify(data),
			encoding: 'utf8'
		};
		if (! jwtKeyParams[algorithm]) {
			throw new Error('Unsupported JWT algorithm');
		}
		if (! jwtKeyParams[algorithm].type) {
			sd.secret = key;
		} else {
			sd.privateKey = key;
		}
		r = jws.sign(sd);
		if (! r) {
			throw new Error('JWT signing failed');
		}
	} catch (e) {
		throw e;
	}
	return r;
}

module.exports = createJwt;
