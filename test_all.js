/* Just sniffs on every interface */
pcap	= require('./pcapjs');
os	= require('os');

	var intfs = os.networkInterfaces();
	for(var v in intfs) {
		console.log("interface:", v);
		var intf = intfs[v];
		intf.p = new pcap.create(v, "icmp or icmp6 or arp", 1, 1000);

		intf.p.on('pkt', function(res) {
			res.pkt = new Buffer(res.pkt);
			var dec = pcap.decode.packet(res);
			console.log("DECODED:", dec);
		});
	}

	console.log("knowd.");
