#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const Optist = require('optist');
const ou = require('optist/util');

const jwtKeyParams = {
	'RS256': {
		type: 'rsa',
		options: {
			modulusLength: 2048,
			publicKeyEncoding: {
				type: 'pkcs1',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs1',
				format: 'pem'
			}
		}
	},
	'RS384': {
		type: 'rsa',
		options: {
			modulusLength: 3072,
			publicKeyEncoding: {
				type: 'pkcs1',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs1',
				format: 'pem'
			}
		}
	},
	'RS512': {
		type: 'rsa',
		options: {
			modulusLength: 4096,
			publicKeyEncoding: {
				type: 'pkcs1',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs1',
				format: 'pem'
			}
		}
	},
	'ES256': {
		type: 'ec',
		options: {
			namedCurve: 'secp256k1',
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'sec1',
				format: 'pem'
			}
		}
	},
	'ES384': {
		type: 'ec',
		options: {
			namedCurve: 'secp384r1',
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'sec1',
				format: 'pem'
			}
		}
	},
	'ES512': {
		type: 'ec',
		options: {
			namedCurve: 'secp521r1',
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'sec1',
				format: 'pem'
			}
		}
	}
};

var opt = ((new Optist())
		   .opts([ { longName: 'jwt-algorithm',
					 description: 'JWT algorithm for the key pair.',
					 hasArg: true,
					 required: true,
					 optArgCb: ou.allowListCbFactory(Object.keys(jwtKeyParams)) },
				   { longName: 'output',
					 description: 'Filename for the secret key.',
					 hasArg: true,
					 required: true,
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'verbose',
					 shortName: 'v',
					 description: 'Enable verbose output.' } ])
		   .help('jwt-keygen')
		   .parse(undefined, 0, 0));

function genJwtKeyPair(jwtAlg) {
	if (! jwtKeyParams[jwtAlg]) {
		return Promise.reject(new Error('Unsupported JWT algorithm'));
	}
	return new Promise(function(resolve, reject) {
		crypto.generateKeyPair(jwtKeyParams[jwtAlg].type,
							   jwtKeyParams[jwtAlg].options,
							   function(e, publicKey, privateKey) {
								   if (e) {
									   return reject(e);
								   }
								   return resolve({ publicKey: publicKey,
													privateKey: privateKey });
							   });
	});
}

function writeFile(fn, data, options) {
	return new Promise(function(resolve, reject) {
		fs.writeFile(fn, data, options, function(e) {
			if (e) {
				return reject(e);
			}
			return resolve(true);
		});
	});
}

(async function() {
	try {
		var k = await genJwtKeyPair(opt.value('jwt-algorithm'));
		await writeFile(opt.value('output'),
						k.privateKey,
						{ encoding: 'utf8',  mode: 0o600, flag: 'wx' });
		await writeFile(opt.value('output') + '.pub',
						k.publicKey,
						{ encoding: 'utf8',  mode: 0o644, flag: 'wx' });
	} catch (e) {
		console.log(e);
		process.exit(1);
	}
})();
