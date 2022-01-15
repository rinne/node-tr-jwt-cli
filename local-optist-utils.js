'use strict';

function nameValuePairCb(s) {
	let name, separator, value;
	let m = s.match(/^([^:=+]+)(:|=|@)(.*)$/);
	if (! m) {
		return undefined;
	}
	name = m[1];
	separator = m[2];
	switch (separator) {
	case ':':
		value = m[3];
		break;
	case '=':
	case '@':
		value = Number.parseInt(m[3]);
		if (! (Number.isFinite(value) && (value.toString() === m[3]))) {
			return undefined;
		}
		if (separator === '@') {
			value += Math.floor(Date.now() / 1000)
		}
		break;
	default:
		return undefined;
	}
	return { name: name, value: value };
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
