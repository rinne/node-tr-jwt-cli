#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const jwk = require('pem-jwk');
const Optist = require('optist');
const ou = require('optist/util');
const base64url = require('base64url');

const parseJwtToken = require('./parse-jwt-token.js');
const unixTimeToUtcString = require('./unix-time-to-utc-string.js');

var context = {
	verbose: false,
	jwtConf: {},
	token: null,
	tokenData: null
};

function readProcessInput() {
	return new Promise(function(resolve, reject) {
		let r = '';
		let completed = false;
		process.stdin.setEncoding('utf-8');
		process.stdin.on('data', function(d) {
			if (completed) {
				return;
			}
			r += d;
				
		});
		process.stdin.on('end', function() {
			if (completed) {
				return;
			}
			completed = true;
			resolve(r);
		});
		process.stdin.on('error', function() {
			if (completed) {
				return;
			}
			completed = true;
			reject(new Error('Unable to read input'));
		});
	});
}

var opt = ((new Optist())
		   .opts([ { longName: 'public-key-file',
					 description: 'Read token signature public key from file.',
					 hasArg: true,
					 optArgCb: ou.fileContentsStringCb,
					 conflictsWith: [ 'secret' ] },
				   { longName: 'secret',
					 description: 'Symmetric token signing secret.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb,
					 conflictsWith: [ 'public-key-file' ] },
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
	if (opt.value('public-key-file')) {
		[ { format: 'pem' },
		  { format: 'jwk' },
		  { format: 'der', type: 'pkcs1' },
		  { format: 'der', type: 'spki' }].some(function(opts) {
			  try {
				  context.jwtConf.publicKey = crypto.createPublicKey(
					  { key: opt.value('public-key-file'),
						type: opts.type,
						format: opts.format });
			  } catch (e) {
				  context.jwtConf.publicKey = undefined;
			  }
			  return !!context.jwtConf.publicKey;
		  });
		if (! context.jwtConf.publicKey) {
			console.log('Unable to read key file');
			process.exit(1);
		}
		if (! ((context.jwtConf.publicKey.type === 'public') &&
			   ((context.jwtConf.publicKey.asymmetricKeyType === 'rsa') ||
				(context.jwtConf.publicKey.asymmetricKeyType === 'ec')))) {
			console.log('Unexpected key type');
			process.exit(1);
		}
		switch (context.jwtConf.publicKey.asymmetricKeyType) {
		case 'rsa':
			context.jwtConf.publicKeyDer =
				context.jwtConf.publicKey.export({ type: 'pkcs1', format: 'der' });
			context.jwtConf.publicKeyPem =
				context.jwtConf.publicKey.export({ type: 'pkcs1', format: 'pem' });
			context.jwtConf.publicKeyJwk = jwk.pem2jwk(context.jwtConf.publicKeyPem);
			if (! (context.jwtConf.publicKeyJwk.kty === 'RSA')) {
				console.log('Unexpected key type');
				process.exit(1);
			}
			context.jwtConf.algorithms = [ 'RS256', 'RS384', 'RS512' ];
			break;
		case 'ec':
			context.jwtConf.publicKeyDer =
				context.jwtConf.publicKey.export({ type: 'spki', format: 'der' });
			context.jwtConf.publicKeyPem =
				context.jwtConf.publicKey.export({ type: 'spki', format: 'pem' });
			context.jwtConf.algorithms = [ 'ES256', 'ES384', 'ES512' ];
			context.jwtConf.publicKeyJwk = { kty: 'EC' };
			break;
		}
	} else if (opt.value('secret')) {
		context.jwtConf.secret = opt.value('secret');
		context.jwtConf.algorithms = [ 'HS256', 'HS384', 'HS512' ];
	} else {
		console.log('Either public key or secret is required.');
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
