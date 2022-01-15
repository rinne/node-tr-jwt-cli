#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const Optist = require('optist');
const ou = require('optist/util');
const base64url = require('base64url');
const lou = require('./local-optist-utils.js');
const readKeyFile = require('./read-key-file.js');
const getEcCurveName = require('./get-ec-curve-name.js');
const jwtKeyParams = require('./data-jwt-key-params.js');
const readProcessInput = require('./read-process-input.js');
const parseJwtToken = require('./parse-jwt-token.js');
const unixTimeToUtcString = require('./unix-time-to-utc-string.js');

var context = {
	verbose: false,
	jwtConf: {},
	token: null,
	tokenData: null
};

var opt = ((new Optist())
		   .opts([ { longName: 'public-key-file',
					 description: 'Read token signature public key from file.',
					 hasArg: true,
					 optArgCb: ou.existingFileNameCb,
					 conflictsWith: [ 'secret', 'secret-hex' ] },
				   { longName: 'secret',
					 description: 'Symmetric token signing secret.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb,
					 conflictsWith: [ 'secret-hex', 'public-key-file' ] },
				   { longName: 'secret-hex',
					 description: 'Symmetric secret for token signing in hexadecimal.',
					 hasArg: true,
					 optArgCb: lou.hexBufCb,
					 conflictsWith: [ 'secret', 'public-key-file' ] },
				   { longName: 'jwt-algorithm',
					 shortName: 'a',
					 multi: true,
					 description: 'Accept only a given JWT algorithm.',
					 hasArg: true,
					 optArgCb: ou.allowListCbFactory(Object.keys(jwtKeyParams)) },
				   { longName: 'strict',
					 description: 'Be strict!' },
				   { longName: 'verbose',
					 shortName: 'v',
					 description: 'Enable verbose output.' },
				   { longName: 'token',
					 description: 'Token to be verified.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb } ])
		   .help('jwt-validate')
		   .parse(undefined, 0, 0));

(async function() {
	context.verbose = opt.value('verbose');
	context.strict = opt.value('strict');
	if (opt.value('secret')) {
		context.jwtConf.secret = opt.value('secret');
	} else if (opt.value('secret-hex')) {
		context.jwtConf.secret = opt.value('secret-hex');
	}
	try {
		if (opt.value('public-key-file')) {
			let k = readKeyFile(opt.value('public-key-file'), false);
			context.jwtConf.publicKey = k.publicKey;
			context.jwtConf.publicKeyDer =
				context.jwtConf.publicKey.export({ type: 'spki', format: 'der' });
			context.jwtConf.publicKeyPem =
				context.jwtConf.publicKey.export({ type: 'spki', format: 'pem' });
			switch (context.jwtConf.publicKey.asymmetricKeyType) {
			case 'rsa':
				context.jwtConf.algorithms = [ 'RS256', 'RS384', 'RS512' ];
				if (! context.strict) {
					context.jwtConf.algorithms.push('PS256', 'PS384', 'PS512');
				}
				break;
			case 'rsa-pss':
				context.jwtConf.algorithms = [ 'PS256', 'PS384', 'PS512' ];
				if (! context.strict) {
					context.jwtConf.algorithms.push('RS256', 'RS384', 'RS512');
				}
				break;
			case 'ec':
				let cn = getEcCurveName(context.jwtConf.publicKey);
				Object.keys(jwtKeyParams).some(function(a) {
					if ((jwtKeyParams[a].type === 'ec') &&
						(!!jwtKeyParams[a].options) &&
						(jwtKeyParams[a].options.namedCurve === cn)) {
						context.jwtConf.algorithms = [ a ];
						return true;
					}
					return false;
				});
				if (! context.jwtConf.algorithms) {
					throw new Error('Unexpected EC key type');
				}
				break;
			default:
				throw new Error('Unexpected key type');
			}
		} else if (context.jwtConf.secret) {
			context.jwtConf.algorithms = [ 'HS256', 'HS384', 'HS512' ];
		} else {
			throw new Error('Either public key or secret is required.');
		}
		if (opt.value('jwt-algorithm').length > 0) {
			context.jwtConf.algorithms = context.jwtConf.algorithms.filter(function(a) {
				return (opt.value('jwt-algorithm').indexOf(a) >= 0); });
		}
		if (context.jwtConf.algorithms.length < 1) {
			throw new Error('Allowed algorithms mismatch with key');
		}
	} catch (e) {
		console.log(e.message);
		process.exit(1);
	}
	try {
		let t = opt.value('token') ? opt.value('token') : await readProcessInput();
		let d = parseJwtToken(t);
		if (! (d && d.tokenHeaderData && (! d.errors))) {
			if (d.tokenHeaderData) {
				context.tokenHeaderData  = d.tokenHeaderData;
			}
			if (d.tokenPayloadData) {
				context.tokenPayloadData  = d.tokenPayloadData;
			}
			throw new Error('Invalid token format');
		}
		Object.assign(context, d);
		context.tokenData = jwt.verify(context.token,
									   (context.jwtConf.secret ?
										context.jwtConf.secret :
										context.jwtConf.publicKey),
									   { algorithms: context.jwtConf.algorithms } );
		if (! context.tokenData) {
			throw new Error('Invalid token');
		}
		// jwt.verify has already done mandatory checks and failed with non-valid token.
		if (context.strict) {
			if ('exp' in context.tokenData) {
				if (! Number.isSafeInteger(context.tokenData.exp)) {
					throw new Error('Expiration time not a number in strict mode');
				}
				if (context.tokenData.exp >
					(Math.floor(Date.now() / 1000) + (10 * 365.25 * 24 * 60 * 60))) {
					throw new Error('Expiration time over 10 years in future in strict mode');
				}
			} else {
				throw new Error('Expiration time missing in strict mode');
			}
			if (! (('nbf' in context.tokenData) || ('iss' in context.tokenData))) {
				throw new Error('Issue and not before times are both missing in strict mode');
			}
			if ('nbf' in context.tokenData) {
				if (! Number.isSafeInteger(context.tokenData.exp)) {
					throw new Error('Not before time not a number in strict mode');
				}
			}
			if ('iat' in context.tokenData) {
				if (! Number.isSafeInteger(context.tokenData.iat)) {
					throw new Error('Issue time not a number in strict mode');
				}
				if (context.tokenData.iat > Math.floor(Date.now() / 1000)) {
					throw new Error('Issue time in future in strict mode');
				}
			}
			if (('exp' in context.tokenData) && ('iat' in context.tokenData)) {
				if (context.tokenData.iat > context.tokenData.exp) {
					throw new Error('Issue time after expiration in strict mode');
				}
				if ((context.tokenData.exp - context.tokenData.iat) >
					(10 * 365.25 * 24 * 60 * 60)) {
					throw new Error('Expiration time over 10 years after issue time in strict mode');
				}
			}
			if (('exp' in context.tokenData) && ('iat' in context.tokenData)) {
				if (context.tokenData.iat > context.tokenData.exp) {
					throw new Error('Issue time after expiration in strict mode');
				}
				if ((context.tokenData.exp - context.tokenData.iat) >
					(10 * 365.25 * 24 * 60 * 60)) {
					throw new Error('Expiration time over 10 years after issue time in strict mode');
				}
			}
			if (('exp' in context.tokenData) && ('nbf' in context.tokenData)) {
				if ((context.tokenData.exp - context.tokenData.nbf) >
					(10 * 365.25 * 24 * 60 * 60)) {
					throw new Error('Validity period over 10 years in strict mode');
				}
			}
			['iss', 'aud', 'prn', 'jti',  'typ'].forEach(function(p) {
				if (p in context.tokenData) {
					if (typeof(context.tokenData[p]) !== 'string') {
						let m = 'Reserved property "' + p + '" not a string in strict mode';
						throw new Error(m);
					}
				}
			});
		}
	} catch (e) {
		context.tokenData = null;
		console.log('Token validation failed: ' + e.message);
		if (context.verbose &&
			(context.tokenHeaderData || context.tokenPayloadData)) {
			console.log('WARNING! WARNING! WARNING! WARNING! WARNING!');
			console.log('The following information is not validated.');
			if (context.tokenHeaderData) {
				console.log('unvalidated token header: ' +
							JSON.stringify(context.tokenHeaderData, null, 2));
			}
			if (context.tokenPayloadData) {
				console.log('unvalidated token payload: ' +
							JSON.stringify(context.tokenPayloadData, null, 2));
			}
		}
		process.exit(1);
	}
	console.log('Token successfully verified');
	if (context.verbose) {
		if (context.tokenData.iat) {
			console.log('Issued at ' +
						unixTimeToUtcString(context.tokenData.iat));
		}
		if (context.tokenData.nbf) {
			console.log('Valid not before ' +
						unixTimeToUtcString(context.tokenData.nbf));
		}
		if (context.tokenData.exp) {
			console.log('Expires at ' +
						unixTimeToUtcString(context.tokenData.exp));
		}
		if (context.tokenHeaderData) {
			console.log('token header: ' +
						JSON.stringify(context.tokenHeaderData, null, 2));
		}
		console.log('token payload: ' +
					JSON.stringify(context.tokenData, null, 2));
	}
	process.exit();
})();
