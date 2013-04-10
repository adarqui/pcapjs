/* pcapjs
 *
 *  Alot of thanks to mranney (https://github.com/mranney),
 *  I Ripped some of his code & used his module/protocol header parsing as a guideline
 *
 * -- adarqui (github.com/adarqui && adarq.org)
 *
 *
 *
 * Building:
 *
 *  node-gyp configure build
 *
 *
 * Usage:
 *
 *  var p = require("./pcapjs.js");
 *  var pc = p.create("eth0", "icmp", 1, 1000);
 *  pc.on("pkt", function(res) {
 *   res.pkt = new Buffer(res.pkt); var dec = p.decode.packet(res.pkt; c.log(res.pkg);
 *  ));
 *
 *  that's is really..
 *
 *  You can create multiple interfaces each with it's own filter. Don't use 'any',
 *  instead provide a list of interfaces. os.networkInterfaces() etc.
 */


var deps = {
	pcapjs	: require("./pcapjs.js"),
}

var argv = process.argv;

if(argv.length < 3) {
	console.log("Usage: node test_cap.js interface,filter eth0,icmp tun0,\"port 53 and udp\" ...");
	process.exit(0);
}

var cb_pcap_pkt = function(res) {
	res.pkt = new Buffer(res.pkt);
	var decoded = deps.pcapjs.decode.packet(res);
	console.log("DECODED: ", decoded);
}


argv = argv.splice(2,argv.length);
console.log(argv);

var caps = {};

for(var v in argv) {
	var arg = argv[v].split(',');

	console.log(arg);

	console.log(arg[0], arg[1]);
	if(arg[1] == undefined) {
		arg[1] = "none";
	}

	var pc = new deps.pcapjs.create(arg[0], arg[1], 1, 1000, cb_pcap_pkt);
	caps[arg[0]+arg[1]] = pc;
	console.log(pc);

	pc.on("pkt", cb_pcap_pkt);
}

setInterval(function() {
}, 10);
