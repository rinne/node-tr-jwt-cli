'use strict';

const crypto = require('crypto');
const fs = require('fs');
const jwk = require('pem-jwk');

function readKeyFile(filename, secret) {
	let s, r;
	try {
		if (! fs.statSync(filename).isFile()) {
			throw new Error('Invalid file');
		}
		s = fs.readFileSync(filename, { encoding: 'utf8', flag: 'r' } );
		if (! s) {
			throw new Error('File read error');
		}
		[ { format: 'pem' },
		  { format: 'jwk' },
		  { format: 'der', type: 'pkcs1' },
		  { format: 'der', type: 'pkcs8' },
		  { format: 'der', type: 'spki' },
		  { format: 'der', type: 'sec1' }].some(function(opts) {
			  try {
				  let sk, pk;
				  if (secret) {
					  sk = crypto.createPrivateKey(
						  { key: s,
							type: opts.type,
							format: opts.format });
				  }
				  pk = crypto.createPublicKey(
					  { key: s,
						type: opts.type,
						format: opts.format });
				  if (! ((pk && pk.type === 'public') &&
						 ((sk && sk.type === 'private') || (! secret)))) {
					  throw new Error('Unable to parse key file');
				  }
				  r = {};
				  r.publicKey = pk;
				  if (secret) {
					  r.privateKey = sk;
				  }
			  } catch (e) {
				  r = undefined;
			  }
			  return !!r;
		  });
		if (! r) {
			throw new Error('Unable to parse key file');
		}
	} catch (e) {
		throw e;
	}
	return r;
}

module.exports = readKeyFile;
