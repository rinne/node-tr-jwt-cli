'use strict';

const crypto = require('crypto');
const fs = require('fs');
const jwk = require('pem-jwk');

function getEcCurveName(publicKey) {
	if (! (publicKey &&
		   publicKey.asymmetricKeyType &&
		   (publicKey.asymmetricKeyType === 'ec'))) {
		throw new Error('Bad key');
	}
	if (publicKey.asymmetricKeyDetails &&
		publicKey.asymmetricKeyDetails.namedCurve) {
		return publicKey.asymmetricKeyDetails.namedCurve;
	}
	// Fallback for node < 16
	let der = publicKey.export({ type: 'spki', format: 'der' });
	// OID 1.3.132.0.10
	if (der.includes('06052B8104000A', 'hex')) {
		return 'secp256k1';
	}
	// OID 1.3.132.0.34
	if (der.includes('06052B81040022', 'hex')) {
		return 'secp384r1';
	}
	// OID 1.3.132.0.35
	if (der.includes('06052B81040023', 'hex')) {
		return 'secp521r1';
	}
	throw new Error('Unknown EC curve');
}

module.exports = getEcCurveName;
