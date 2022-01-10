'use strict';

module.exports = {
	'HS256': {
		hash: 'sha256'
	},
	'HS384': {
		hash: 'sha384'
	},
	'HS512': {
		hash: 'sha512'
	},
	'RS256': {
		type: 'rsa',
		hash: 'sha256',
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
		hash: 'sha384',
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
		hash: 'sha512',
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
	'PS256': {
		type: 'rsa-pss',
		hash: 'sha256',
		options: {
			modulusLength: 2048,
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem'
			}
		}
	},
	'PS384': {
		type: 'rsa-pss',
		hash: 'sha384',
		options: {
			modulusLength: 3072,
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem'
			}
		}
	},
	'PS512': {
		type: 'rsa-pss',
		hash: 'sha512',
		options: {
			modulusLength: 4096,
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem'
			}
		}
	},
	'ES256': {
		type: 'ec',
		hash: 'sha256',
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
		hash: 'sha384',
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
		hash: 'sha512',
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
