'use strict';

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

module.exports = readProcessInput;
