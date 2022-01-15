#!/usr/bin/env node
'use strict';

const Optist = require('optist');
const ou = require('optist/util');
const lou = require('./local-optist-utils.js');
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
		   .opts([ { longName: 'verbose',
					 shortName: 'v',
					 description: 'Enable verbose output.' },
				   { longName: 'token',
					 description: 'Token to be parsed.',
					 hasArg: true,
					 optArgCb: ou.nonEmptyCb } ])
		   .help('jwt-parse')
		   .parse(undefined, 0, 0));

(async function() {
	try {
		context.verbose = opt.value('verbose');
		let t = opt.value('token') ? opt.value('token') : await readProcessInput();
		let d = parseJwtToken(t);
		if (! (d && d.tokenHeaderData && d.tokenPayloadData && d.tokenSignatureRaw && (! d.errors))) {
			throw new Error('Invalid token format');
		}
		context.tokenHeaderData = d.tokenHeaderData;
		context.tokenPayloadData = d.tokenPayloadData;
		context.tokenSignatureLength = d.tokenSignatureRaw.length;
	} catch (e) {
		console.log(e.message);
		process.exit(1);
	}
	console.log('token header: ' +
				JSON.stringify(context.tokenHeaderData, null, 2));
	console.log('token payload: ' +
				JSON.stringify(context.tokenPayloadData, null, 2));
	console.log('token signature blob length: ' + context.tokenSignatureLength + ' bytes');
	if (Number.isSafeInteger(context.tokenPayloadData.iat)) {
		console.log('issued: ' +
					unixTimeToUtcString(context.tokenPayloadData.iat) +
					' UTC');
	}
	if (Number.isSafeInteger(context.tokenPayloadData.nbf)) {
		console.log('valid not before: ' +
					unixTimeToUtcString(context.tokenPayloadData.nbf) +
					' UTC');
	}
	if (Number.isSafeInteger(context.tokenPayloadData.exp)) {
		console.log('expiration time: ' +
					unixTimeToUtcString(context.tokenPayloadData.exp) +
					' UTC');
	}
	if (typeof(context.tokenPayloadData.iss) === 'string') {
		console.log('issuer: ' + context.tokenPayloadData.iss);
	}
	if (typeof(context.tokenPayloadData.sub) === 'string') {
		console.log('subject: ' + context.tokenPayloadData.sub);
	}
	if (typeof(context.tokenPayloadData.aud) === 'string') {
		console.log('audience: ' + context.tokenPayloadData.aud);
	}
	if (typeof(context.tokenPayloadData.jti) === 'string') {
		console.log('jwt id: ' + context.tokenPayloadData.jti);
	}
	process.exit();
})();
