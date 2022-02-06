#!/usr/bin/env node
'use strict';

const base64url = require('base64url');

function parseJwtToken(token) {
	let r = { };
	let errors = [];
	let m = token.match(/^\s*(Authorization:\s+)?(Bearer\s+)?(([^\s\.]+)\.([^\s\.]+)\.([^\s\.]+))\s*$/i);
	if (! m) {
		errors.push(new Error);
		r.errors = errors;
		return r;
	}
	r.token = m[3];
	r.tokenHeader = m[4];
	r.tokenPayload = m[5];
	r.tokenSignature = m[6];
	try {
		r.tokenPayloadRaw = base64url.toBuffer(r.tokenPayload);
		r.tokenPayloadString = r.tokenPayloadRaw.toString('utf8');
		r.tokenPayloadData = JSON.parse(r.tokenPayloadString);
	} catch (e) {
		errors.push(e);
	}
	try {
		r.tokenHeaderRaw = base64url.toBuffer(r.tokenHeader);
		r.tokenHeaderString = r.tokenHeaderRaw.toString('utf8');
		r.tokenHeaderData = JSON.parse(r.tokenHeaderString);
	} catch (e) {
		errors.push(e);
	}
	try {
		r.tokenSignatureRaw = base64url.toBuffer(r.tokenSignature);
	} catch (e) {
		errors.push(e);
	}
	if (errors.length > 0) {
		r.errors = errors;
	}
	return r;
}

module.exports = parseJwtToken;
