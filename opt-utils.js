'use strict';

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

function hexBufCb(s) {
	if (! s.match(/^([0-9a-fA-F][0-9a-fA-F])+$/)) {
		return undefined;
	}
	s = Buffer.from(s, 'hex');
	return s;
}

module.exports = {
	nameValuePairCb: nameValuePairCb,
	hexBufCb: hexBufCb
};
