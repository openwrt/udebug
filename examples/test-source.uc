#!/usr/bin/env ucode
let udebug = require("udebug");

udebug.init("./udebug.sock");
let buf = udebug.create_ring({
	name: "counter",
	size: 256,
	entries: 128,
});

if (!buf) {
	warn(`Failed to create buffer\n`);
	exit(1);
}

let count = 0;
signal('SIGINT', () => exit(0));
signal('SIGTERM', () => exit(0));
while (true) {
	buf.add(`count=${count}`);
	if (count++ > 1000)
		sleep(1000);
}
