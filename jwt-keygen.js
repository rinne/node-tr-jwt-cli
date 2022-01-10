#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const Optist = require('optist');
const ou = require('optist/util');
const readKeyFile = require('./read-key-file.js');
const jwtKeyParams = require('./data-jwt-key-params.js');

var opt = ((new Optist())
		   .opts([ { longName: 'jwt-algorithm',
					 shortName: 'a',
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
	if (! jwtKeyParams[jwtAlg].type) {
		return Promise.reject(new Error('JWT algorithm not a public key type'));
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
		readKeyFile(opt.value('output'), true);
		readKeyFile(opt.value('output') + '.pub', false);
	} catch (e) {
		console.log(e);
		process.exit(1);
	}
})();
