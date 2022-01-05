'use strict';

function unixTimeToUtcString(unixTimestamp) {
	if (! Number.isFinite(unixTimestamp)) {
		throw new Error('Invalid Unix timestamp');
	}
	return (((new Date(unixTimestamp * 1000))
			 .toISOString()
			 .replace(/[TZ]/g, ' ')
			 .replace(/\.\d+\s*$/,'')) + ' UTC');
}

module.exports = unixTimeToUtcString;
