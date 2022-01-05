#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const jwk = require('pem-jwk');
const Optist = require('optist');
const ou = require('optist/util');
const uuidv4 = require('uuid').v4;
const base64url = require('base64url');

const parseJwtToken = require('./parse-jwt-token.js');

var context = {
	verbose: false,
	jwtConf: {},
	token: null,
	tokenData: null
};

function nameValuePairCb(s) {
	let m = s.match(/^([^:=]+)([:=])(.*)$/);
	if (! m) {
		return undefined;
	}
	if (m[2] === ':') {
		return { name: m[1], value: m[3] };
	}
	if (m[2] === '=') {
		let i = Number.parseInt(m[3]);
		if (! (Number.isFinite(i) && (i.toString() === m[3]))) {
			return undefined;
		}
		return { name: m[1], value: i };
	}
	return undefined;
}

var opt = ((new Optist())
		   .opts([ { longName: 'token-ttl',
					 description: 'Default validity time for tokens in seconds.',
					 hasArg: true,
					 defaultValue: '3600',
					 optArgCb: ou.integerWithLimitsCbFactory(1, 999999999999) },
				   { longName: 'token-issuer',
					 description: 'Issuer name to be included into tokens.',
					 hasArg: true,
					 defaultValue: 'anonymous',
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'token-subject',
					 description: 'Subject name to be included into tokens.',
					 hasArg: true,
					 defaultValue: 'anonymous',
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'token-property',
					 description: 'Extra name:value pair to be included into a token.',
					 hasArg: true,
					 multi: true,
					 optArgCb: nameValuePairCb },
				   { longName: 'token-key-id',
					 description: 'Override key-id in token.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb },
				   { longName: 'skip-validation',
					 description: 'Do not validate the created token.' },
				   { longName: 'secret-key-file',
					 description: 'Read token signing key from file.',
					 hasArg: true,
					 optArgCb: ou.fileContentsStringCb,
					 conflictsWith: [ 'secret' ] },
			       { longName: 'hash-length',
					 description: 'Hash length for signatures.',
					 hasArg: true,
					 defaultValue: '256',
					 optArgCb: ou.integerWithLimitsCbFactory(128,1024) },
				   { longName: 'secret',
					 description: 'Symmetric secret for token signing.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb,
					 conflictsWith: [ 'secret-key-file' ] },
				   { longName: 'verbose',
					 shortName: 'v',
					 description: 'Enable verbose output.' } ])
		   .help('jwt-create')
		   .parse(undefined, 0, 0));

(function() {
	context.verbose = opt.value('verbose');
	context.jwtConf.property = opt.value('token-property');
	context.jwtConf.issuer = opt.value('token-issuer');
	context.jwtConf.subject = opt.value('token-issuer');
	context.jwtConf.ttl = opt.value('token-ttl');
	context.jwtConf.validate = !opt.value('skip-validation');
	context.jwtConf.hashLength = opt.value('hash-length');
	if ([256, 384, 512].indexOf(context.jwtConf.hashLength) < 0) {
		console.log('Invalid hash length.');
		process.exit(1);
	}
	if (opt.value('secret-key-file')) {
		try {
			[ { format: 'pem' },
			  { format: 'jwk' },
			  { format: 'der', type: 'pkcs1' },
			  { format: 'der', type: 'spki' }].some(function(opts) {
				  try {
					  context.jwtConf.secretKey = crypto.createPrivateKey(
						  { key: opt.value('secret-key-file'),
							type: opts.type,
							format: opts.format });
					  context.jwtConf.publicKey = crypto.createPublicKey(
						  { key: opt.value('secret-key-file'),
							type: opts.type,
							format: opts.format });
				  } catch (e) {
					  context.jwtConf.secretKey = undefined;
					  context.jwtConf.publicKey = undefined;
				  }
				  return !!(context.jwtConf.secretKey && context.jwtConf.publicKey);
			  });
			if (! context.jwtConf.publicKey) {
				throw new Error('Unable to read key file');
			}
			if (! ((context.jwtConf.publicKey.type === 'public') &&
				   ((context.jwtConf.publicKey.asymmetricKeyType === 'rsa') ||
					(context.jwtConf.publicKey.asymmetricKeyType === 'ec')))) {
				throw new Error('Unexpected key type');
			}
			switch (context.jwtConf.publicKey.asymmetricKeyType) {
			case 'rsa':
				context.jwtConf.publicKeyDer =
					context.jwtConf.publicKey.export({ type: 'pkcs1', format: 'der' });
				context.jwtConf.publicKeyPem =
					context.jwtConf.publicKey.export({ type: 'pkcs1', format: 'pem' });
				context.jwtConf.publicKeyJwk = jwk.pem2jwk(context.jwtConf.publicKeyPem);
				if (! (context.jwtConf.publicKeyJwk.kty === 'RSA')) {
					throw new Error('Unexpected key type');
				}
				switch (context.jwtConf.hashLength) {
				case 256:
					context.jwtConf.algorithm = 'RS256';
					context.jwtConf.hashName = 'sha256';
					break;
				case 384:
					context.jwtConf.algorithm = 'RS384';
					context.jwtConf.hashName = 'sha384';
					break;
				case 512:
					context.jwtConf.algorithm = 'RS512';
					context.jwtConf.hashName = 'sha512';
					break;
				}
				break;
			case 'ec':
				context.jwtConf.publicKeyDer =
					context.jwtConf.publicKey.export({ type: 'spki', format: 'der' });
				context.jwtConf.publicKeyPem =
					context.jwtConf.publicKey.export({ type: 'spki', format: 'pem' });
				context.jwtConf.publicKeyJwk = { kty: 'EC' };
				switch (context.jwtConf.hashLength) {
				case 256:
					if (context.jwtConf.publicKey.asymmetricKeyDetails) {
						if (context.jwtConf.publicKey.asymmetricKeyDetails.namedCurve !==
							'secp256k1') {
							throw new Error('Unexpected EC curve');
						}
					} else {
						if (! context.jwtConf.publicKeyDer.includes('06052B8104000A', 'hex')) {
							throw new Error('Unable to find OID 1.3.132.0.10 in EC key');
						}
					}
					context.jwtConf.algorithm = 'ES256';
					context.jwtConf.hashName = 'sha256';
					break;
				case 384:
					if (context.jwtConf.publicKey.asymmetricKeyDetails) {
						if (context.jwtConf.publicKey.asymmetricKeyDetails.namedCurve !==
							'secp384r1') {
							throw new Error('Unexpected EC curve');
						}
					} else {
						if (! context.jwtConf.publicKeyDer.includes('06052B81040022', 'hex')) {
							throw new Error('Unable to find OID 1.3.132.0.34 in EC key');
						}
					}
					context.jwtConf.algorithm = 'ES384';
					context.jwtConf.hashName = 'sha384';
					break;
				case 512:
					if (context.jwtConf.publicKey.asymmetricKeyDetails) {
						if (context.jwtConf.publicKey.asymmetricKeyDetails.namedCurve !==
							'secp521r1') {
							throw new Error('Unexpected EC curve');
						}
					} else {
						if (! context.jwtConf.publicKeyDer.includes('06052B81040023', 'hex')) {
							throw new Error('Unable to find OID 1.3.132.0.354 in EC key');
						}
					}
					context.jwtConf.algorithm = 'ES512';
					context.jwtConf.hashName = 'sha512';
					break;
				}
				break;
			}
		} catch(e) {
			console.log('Invalid private key: ' + e.message);
			process.exit(1);
		}
		context.jwtConf.keyId = (crypto
						.createHash(context.jwtConf.hashName)
						.update(context.jwtConf.publicKeyDer)
						.digest('base64')
						.replace(/[^a-zA-Z]/g, '')
						.toLowerCase()
						.slice(0, 12));
	} else if (opt.value('secret')) {
			switch (context.jwtConf.hashLength) {
			case 256:
				context.jwtConf.algorithm = 'HS256';
				context.jwtConf.hashName = 'sha256';
				break;
			case 384:
				context.jwtConf.algorithm = 'HS384';
				context.jwtConf.hashName = 'sha384';
				break;
			case 512:
				context.jwtConf.algorithm = 'HS512';
				context.jwtConf.hashName = 'sha512';
				break;
			}
		context.jwtConf.secret = opt.value('secret');
	} else {
		console.log('Either secret key or secret is required.');
		process.exit(1);
	}
	if (opt.value('token-key-id')) {
		context.jwtConf.keyId = opt.value('token-key-id');
	}
	try {
		let a = {
			iss: context.jwtConf.issuer,
			sub: context.jwtConf.subject,
			iat: Math.floor(Date.now() / 1000) - 60,
			exp: Math.floor(Date.now() / 1000) + context.jwtConf.ttl,
			jti: uuidv4()
		};
		if (context.jwtConf.keyId) {
			a.kid = context.jwtConf.keyId;
		}
		context.jwtConf.property.forEach(function(p) {
			a[p.name] = p.value;
		});
		let t = jwt.sign(a,
						 (context.jwtConf.secret ?
						  context.jwtConf.secret :
						  context.jwtConf.secretKey),
						 { algorithm: context.jwtConf.algorithm } );
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
		console.log('Unable to create token: ' + e.message);
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
