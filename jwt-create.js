#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const jwk = require('pem-jwk');
const Optist = require('optist');
const ou = require('optist/util');
const uuidv4 = crypto.randomUUID ? crypto.randomUUID : require('uuid').v4;
const base64url = require('base64url');
const lou = require('./local-optist-utils.js');
const readKeyFile = require('./read-key-file.js');
const parseJwtToken = require('./parse-jwt-token.js');
const getEcCurveName = require('./get-ec-curve-name.js');
const jwtKeyParams = require('./data-jwt-key-params.js');
const createJwt = require('./create-jwt.js');

var context = {
	verbose: false,
	jwtConf: {},
	token: null,
	tokenData: null
};

var opt = ((new Optist())
		   .opts([ { longName: 'jwt-algorithm',
					 shortName: 'a',
					 description: 'Force JWT algorithm to be used.',
					 hasArg: true,
					 optArgCb: ou.allowListCbFactory(Object.keys(jwtKeyParams)) },
				   { longName: 'token-ttl',
					 description: 'Default validity time for tokens in seconds.',
					 hasArg: true,
					 defaultValue: '3600',
					 optArgCb: ou.integerWithLimitsCbFactory(1, 999999999999) },
				   { longName: 'token-issuer',
					 description: 'Issuer name to be included into tokens.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'token-subject',
					 description: 'Subject name to be included into tokens.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'token-property',
					 description: 'Extra name:value pair to be included into tokens.',
					 hasArg: true,
					 multi: true,
					 optArgCb: lou.nameValuePairCb },
				   { longName: 'exclude-token-property',
					 description: 'Exclude property from the token before signing.',
					 hasArg: true,
					 multi: true,
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'token-key-id',
					 description: 'Override key-id in token.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'skip-validation',
					 description: 'Do not validate the created token.' },
				   { longName: 'private-key-file',
					 description: 'Read token signing key from file.',
					 hasArg: true,
					 optArgCb: ou.existingFileNameCb,
					 conflictsWith: [ 'secret', 'secret-hex' ] },
				   { longName: 'secret',
					 description: 'Symmetric secret for token signing.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb,
					 conflictsWith: [ 'secret-hex', 'private-key-file' ] },
				   { longName: 'secret-hex',
					 description: 'Symmetric secret for token signing in hexadecimal.',
					 hasArg: true,
					 optArgCb: lou.hexBufCb,
					 conflictsWith: [ 'secret', 'private-key-file' ] },
				   { longName: 'verbose',
					 shortName: 'v',
					 description: 'Enable verbose output.' } ])
		   .help('jwt-create')
		   .parse(undefined, 0, 0));

(function() {
	context.verbose = opt.value('verbose');
	context.jwtConf.property = opt.value('token-property');
	context.jwtConf.excludeProperty = opt.value('exclude-token-property');
	context.jwtConf.issuer = opt.value('token-issuer') ? opt.value('token-issuer') : undefined;
	context.jwtConf.subject = opt.value('token-subject') ? opt.value('token-subject') : undefined;
	context.jwtConf.ttl = opt.value('token-ttl');
	context.jwtConf.validate = !opt.value('skip-validation');
	if (opt.value('secret')) {
		context.jwtConf.secret = opt.value('secret');
	} else if (opt.value('secret-hex')) {
		context.jwtConf.secret = opt.value('secret-hex');
	}
	if (opt.value('private-key-file')) {
		try {
			let k = readKeyFile(opt.value('private-key-file'), true);
			context.jwtConf.privateKey = k.privateKey;
			context.jwtConf.publicKey = k.publicKey;
			context.jwtConf.publicKeyDer =
				context.jwtConf.publicKey.export({ type: 'spki', format: 'der' });
			context.jwtConf.publicKeyPem =
				context.jwtConf.publicKey.export({ type: 'spki', format: 'pem' });
			switch (context.jwtConf.publicKey.asymmetricKeyType) {
			case 'rsa':
				context.jwtConf.publicKeyJwk = jwk.pem2jwk(context.jwtConf.publicKeyPem);
				if (! opt.value('jwt-algorithm')) {
					let ml;
					if (context.jwtConf.publicKey.asymmetricKeyDetails) {
						ml = context.jwtConf.publicKey.asymmetricKeyDetails.modulusLength;
					} else {
						let b = Buffer.from(context.jwtConf.publicKeyJwk.n, 'base64');
						if (b.length > 0) {
							ml = (b.length * 8) - (8 - Math.ceil(Math.log(b[0]+1) / Math.LN2));
						}
					}
					if (! ml) {
						throw new Error('Unable to extract RSA key modulus length');
					} else if (ml < 256) {
						throw new Error('Insufficient RSA key modulus length');
					} else if (ml <= 2048) {
						context.jwtConf.algorithm = 'RS256';
					} else if (ml < 4096) {
						context.jwtConf.algorithm = 'RS384';
					} else {
						context.jwtConf.algorithm = 'RS512';
					}
				} else if (['RS256', 'RS384', 'RS512'].indexOf(opt.value('jwt-algorithm')) >= 0) {
					context.jwtConf.algorithm = opt.value('jwt-algorithm');
				} else if (['PS256', 'PS384', 'PS512'].indexOf(opt.value('jwt-algorithm')) >= 0) {
					console.warn('Warning: Forcing RSA-PSS mode for plain RSA key');
					context.jwtConf.algorithm = opt.value('jwt-algorithm');
				} else {
					throw new Error('JWT algorithm key mismatch');
				}
				break;
			case 'rsa-pss':
				context.jwtConf.publicKeyJwk = jwk.pem2jwk(context.jwtConf.publicKeyPem);
				if (! opt.value('jwt-algorithm')) {
					let ml;
					if (context.jwtConf.publicKey.asymmetricKeyDetails) {
						ml = context.jwtConf.publicKey.asymmetricKeyDetails.modulusLength;
					} else {
						let b = Buffer.from(context.jwtConf.publicKeyJwk.n, 'base64');
						if (b.length > 0) {
							ml = (b.length * 8) - (8 - Math.ceil(Math.log(b[0]+1) / Math.LN2));
						}
					}
					if (! ml) {
						throw new Error('Unable to extract RSA key modulus length');
					} else if (ml < 256) {
						throw new Error('Insufficient RSA key modulus length');
					} else if (ml <= 2048) {
						context.jwtConf.algorithm = 'PS256';
					} else if (ml < 4096) {
						context.jwtConf.algorithm = 'PS384';
					} else {
						context.jwtConf.algorithm = 'PS512';
					}
				} else if (['PS256', 'PS384', 'PS512'].indexOf(opt.value('jwt-algorithm')) >= 0) {
					context.jwtConf.algorithm = opt.value('jwt-algorithm');
				} else if (['RS256', 'RS384', 'RS512'].indexOf(opt.value('jwt-algorithm')) >= 0) {
					console.warn('Warning: Forcing plain RSA mode for RSA-PSS key');
					context.jwtConf.algorithm = opt.value('jwt-algorithm');
				} else {
					throw new Error('JWT algorithm key mismatch');
				}
				break;
			case 'ec':
				let cn = getEcCurveName(context.jwtConf.publicKey);
				if (! opt.value('jwt-algorithm')) {
					Object.keys(jwtKeyParams).some(function(a) {
						if ((jwtKeyParams[a].type === 'ec') &&
							(!!jwtKeyParams[a].options) &&
							(jwtKeyParams[a].options.namedCurve === cn)) {
							context.jwtConf.algorithm = a;
							return true;
						}
						return false;
					});
					if (! context.jwtConf.algorithm) {
						throw new Error('JWT algorithm key mismatch');
					}
				} else if ((jwtKeyParams[opt.value('jwt-algorithm')].type === 'ec') &&
						   (!!jwtKeyParams[a].options) &&
						   (jwtKeyParams[opt.value('jwt-algorithm')].options.namedCurve === cn)) {
					context.jwtConf.algorithm = opt.value('jwt-algorithm');
				} else {
					throw new Error('JWT algorithm EC key mismatch');
				}
				break;
			}
			context.jwtConf.hashName = jwtKeyParams[context.jwtConf.algorithm].hash;
			context.jwtConf.keyId = (crypto
									 .createHash(context.jwtConf.hashName)
									 .update(context.jwtConf.publicKeyDer)
									 .digest('base64')
									 .replace(/[^a-zA-Z]/g, '')
									 .toLowerCase()
									 .slice(0, 12));
		} catch(e) {
			console.error('Invalid private key: ' + e.message);
			process.exit(1);
		}
	} else if (context.jwtConf.secret) {
		if (! opt.value('jwt-algorithm')) {
			if (context.jwtConf.secret.length <= 32) {
				context.jwtConf.algorithm = 'HS256';
				context.jwtConf.hashName = 'sha256';
			} else if (context.jwtConf.secret.length <= 48) {
				context.jwtConf.algorithm = 'HS384';
				context.jwtConf.hashName = 'sha384';
			} else {
				context.jwtConf.algorithm = 'HS512';
				context.jwtConf.hashName = 'sha512';
			}
		} else if (opt.value('jwt-algorithm') === 'HS256') {
			context.jwtConf.algorithm = 'HS256';
			context.jwtConf.hashName = 'sha256';
		} else if (opt.value('jwt-algorithm') === 'HS384') {
			context.jwtConf.algorithm = 'HS384';
			context.jwtConf.hashName = 'sha384';
		} else if (opt.value('jwt-algorithm') === 'HS512') {
			context.jwtConf.algorithm = 'HS512';
			context.jwtConf.hashName = 'sha512';
		} else {
			throw new Error('JWT algorithm incompatible with shared secret');
		}
	} else {
		console.error('Either private key or secret is required.');
		process.exit(1);
	}
	if (opt.value('token-key-id')) {
		context.jwtConf.keyId = opt.value('token-key-id');
	}
	try {
		let a = {};
		if (context.jwtConf.issuer) {
			a.iss = context.jwtConf.issuer;
		}
		if (context.jwtConf.subject) {
			a.sub = context.jwtConf.subject;
		}
		a.iat = Math.floor(Date.now() / 1000) - 60,
		a.exp = Math.floor(Date.now() / 1000) + context.jwtConf.ttl,
		a.jti = uuidv4()
		if (context.jwtConf.keyId) {
			a.kid = context.jwtConf.keyId;
		}
		context.jwtConf.property.forEach(function(p) {
			a[p.name] = p.value;
		});
		context.jwtConf.excludeProperty.forEach(function(p) {
			if (p === '*') {
				a = {};
			} else {
				delete a[p];
			}
		});
		let t = createJwt(context.jwtConf.algorithm,
						  (context.jwtConf.secret ?
						   context.jwtConf.secret :
						   context.jwtConf.privateKey),
						  a);
		if (! t) {
			throw new Error('token creation failed');
		}
		if (context.jwtConf.validate) {
			let b = jwt.verify(t,
							   (context.jwtConf.secret ?
								context.jwtConf.secret :
								context.jwtConf.publicKey),
							   { algorithms: [ context.jwtConf.algorithm ] } );
			if (! (b && (b.iss === a.iss) && (b.jti === a.jti))) {
				throw new Error('token does not verify');
			}
			context.tokenData = b;
		} else {
			context.tokenData = a;
		}
		context.token = t;
	} catch (e) {
		console.error('Unable to create token: ' + e.message);
		jwt.secret = undefined;
		process.exit(1);
	}
	if (context.verbose) {
		let d = parseJwtToken(context.token);
		if (d && d.tokenHeaderData) {
			console.log('token header: ' + JSON.stringify(d.tokenHeaderData, null, 2));
		}
		console.log('token payload: ' + JSON.stringify(context.tokenData, null, 2));
	}
	console.log(context.token);
	process.exit();
})();
