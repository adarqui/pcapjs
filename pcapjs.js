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
	pcap	: require('./build/Release/pcap'),
	events	: require('events'),
}	










var create = function(iface, filter, promisc, timeout) {
	var pcap = new deps.events.EventEmitter();

	pcap.config = {
		interface	: iface,
		filter		: filter,
		promisc		: promisc,
		timeout		: timeout,
		count: {
			cur		: 0,
			max		: false,
		}
	}

	var po = deps.pcap.open(pcap.config.interface, pcap.config.filter, 1, 1000, function(res) {
		pcap.emit("pkt", res);
	});


	return pcap;
}

exports.create = create;















var debug = console.log;
debug = function() { };


var test = function() {

	/*
	 * A test function
	 */
	
	setInterval(function() {
	}, 1000);

	var dev = deps.pcap.lookupDev();
	debug("dev", dev);

	var devs = deps.pcap.findAllDevs();
	debug("devs", devs);

	deps.os = require('os');
	var intfs = deps.os.networkInterfaces();
	for(var v in intfs) {
		console.log("interface:", v);
		var intf = intfs[v];
		intf.p = new create(v, "icmp or icmp6 or arp", 1, 1000);

		intf.p.on('pkt', function(res) {
			res.pkt = new Buffer(res.pkt);
			var dec = decode.packet(res);
			console.log("DECODED:", dec);
		});
	}
}


exports.test = test;













var open = function(iface, filter, promisc, timeout, cb) {
	debug("open");
	var po = deps.pcap.open(iface, filter, promisc, timeout, cb);
}
exports.open = open;



function lpad(str, len) {
	// ripped from node_pcap by mranney

	while (str.length < len) {
		str = "0" + str;
	}
	return str;
}

var unpack = {

	ethernet_addr: function (raw_packet, offset) {
		// ripped from node_pcap by mranney
		return [
			lpad(raw_packet[offset].toString(16), 2),
			lpad(raw_packet[offset + 1].toString(16), 2),
			lpad(raw_packet[offset + 2].toString(16), 2),
			lpad(raw_packet[offset + 3].toString(16), 2),
			lpad(raw_packet[offset + 4].toString(16), 2),
			lpad(raw_packet[offset + 5].toString(16), 2)
			].join(":");
		},
	ipv4_addr: function (raw_packet, offset) {
		// ripped from node_pcap by mranney
		return [
			raw_packet[offset],
			raw_packet[offset + 1],
			raw_packet[offset + 2],
			raw_packet[offset + 3]
			].join('.');
	},
	ipv6_addr: function (raw_packet, offset) {
		// ripped from node_pcap by mranney
        var ret = '';
        var octets = [];
        for (var i=offset; i<offset+16; i+=2) {
        octets.push(unpack.uint16(raw_packet,i).toString(16));
        }
        var curr_start, curr_len = undefined;
        var max_start, max_len = undefined;
        for(var i = 0; i < 8; i++){
        if(octets[i] == "0"){
            if(curr_start === undefined){
            curr_len = 1;
            curr_start = i;
            }else{
            curr_len++;
            if(!max_start || curr_len > max_len){
                max_start = curr_start;
                max_len = curr_len;
            }
            }
        }else{
            curr_start = undefined;
        }
        }

        if(max_start !== undefined){
            var tosplice = max_start == 0 || (max_start + max_len > 7) ? ":" : "";
            octets.splice(max_start, max_len,tosplice);
            if(max_len == 8){octets.push("");}
        }
        ret = octets.join(":");
        return ret;
    },
    uint16: function (raw_packet, offset) {
	// ripped from node_pcap by mranney
        return ((raw_packet[offset] * 256) + raw_packet[offset + 1]);
    },
    uint16_be: function (raw_packet, offset) {
	// ripped from node_pcap by mranney
        return ((raw_packet[offset+1] * 256) + raw_packet[offset]);
    },
    uint32: function (raw_packet, offset) {
	// ripped from node_pcap by mranney
        return (
            (raw_packet[offset] * 16777216) +
            (raw_packet[offset + 1] * 65536) +
            (raw_packet[offset + 2] * 256) +
            raw_packet[offset + 3]
        );
    },
    uint64: function (raw_packet, offset) {
	// ripped from node_pcap by mranney
        return (
            (raw_packet[offset] * 72057594037927936) +
            (raw_packet[offset + 1] * 281474976710656) +
            (raw_packet[offset + 2] * 1099511627776) +
            (raw_packet[offset + 3] * 4294967296) +
            (raw_packet[offset + 4] * 16777216) +
            (raw_packet[offset + 5] * 65536) +
            (raw_packet[offset + 6] * 256) +
            raw_packet[offset + 7]
        );
    },
 
}



var decode = {

	push_path: function(q,s) {
		q.o.path.push(s);	
	},

	ipv4: function(q) {

		var ipv4 = {
			version		: (q.pkt[q.off] & 240) >> 4,
			header_len	: q.pkt[q.off] & 15,
			header_tot	: (q.pkt[q.off] & 15) * 4,
			total_len	: q.pkt.readUInt16BE(q.off + 2),
			id			: q.pkt.readUInt16BE(q.off + 4),
			flags: {
				df			: (q.pkt[q.off + 6] & 64) >> 6,
				mf			: (q.pkt[q.off + 6] & 32) >> 5,
				reserved	: (q.pkt[q.off + 6] & 128) >> 7,
			},
			frag_off	: ((q.pkt[q.off + 6] & 31) * 256) + q.pkt[q.off + 7],
			ttl			: q.pkt[q.off + 8],
			proto		: q.pkt[q.off + 9],
			cksum		: q.pkt.readUInt16BE(q.off + 10),
			saddr		: unpack.ipv4_addr(q.pkt, q.off+12),
			daddr		: unpack.ipv4_addr(q.pkt, q.off+16),
		}

		if(ipv4.version == 6) {
			var idx = layer3_4[43];
			if(idx == undefined) {
				return undefined;
			}
			idx.x(q);
			return;
		}

		decode.push_path(q,"ipv4");
		debug("IPv4");
		
		q.o.ipv4 = ipv4;
		q.off = q.off + ipv4.header_tot;

		var idx = layer3_4[ipv4.proto];
		if(idx == undefined) {
			return undefined;
		}

		idx.x(q);
	},

	ipv6: function(q) {
		decode.push_path(q,"ipv6");
		debug("IPv6");

		var ipv6 = {
			version		: (q.pkt[q.off] & 240) >> 4,
			traf_class	: ((q.pkt[q.off] & 15) << 4) + (q.pkt[q.off+1] & 240 >> 4),
			flow_label	: ((q.pkt[q.off + 1] & 15) << 16) + (q.pkt[q.off + 2] << 8) + q.pkt[q.off + 3],
			payload_len	: q.pkt.readUInt16BE(q.off + 4),
			next_header	: q.pkt[q.off+6],
			hop_limit	: q.pkt[q.off+7],
			saddr		: unpack.ipv6_addr(q.pkt, q.off+8),
			daddr		: unpack.ipv6_addr(q.pkt, q.off+24),
			hdr_tot		: 40,	
		}

		q.o.ipv6 = ipv6;
		q.off = q.off + ipv6.hdr_tot;

		var idx = layer3_4[ipv6.next_header];
		if(idx == undefined) {
			return undefined;
		}

		idx.x(q);
	},


	udp: function(q) {
		decode.push_path(q, "udp");
		debug("UDP");

		var udp = {
			
			sport		: q.pkt.readUInt16BE(q.off),
			dport		: q.pkt.readUInt16BE(q.off + 2),
			length		: q.pkt.readUInt16BE(q.off + 4),
			cksum		: q.pkt.readUInt16BE(q.off + 6),

			data: {
				off		: q.off + 8,
			}
		};

		udp.data.end = (udp.length + udp.data.off) - 8;
		udp.data.length = (udp.data.end - udp.data.off);

		if(udp.data.length > 0) {
			udp.data.bytes = q.pkt.slice(udp.data.off, udp.data.end);
		}

		q.o.udp = udp;
	},

	tcp: function(q) {
		decode.push_path(q, "tcp");
		debug("TCP");

		var tcp = {
			sport		: q.pkt.readUInt16BE(q.off),
			dport		: q.pkt.readUInt16BE(q.off+2),
			seqno		: q.pkt.readUInt32BE(q.off+4),
			ackno		: q.pkt.readUInt32BE(q.off+8),
			data_off	: (q.pkt[q.off+12] & 0xf0) >> 4,
			header_len	: {},
			reserved	: q.pkt[q.off+12] & 15,
			flags: {
				cwr		: (q.pkt[q.off+13] & 128) >> 7,
				ece		: (q.pkt[q.off+13] & 64) >> 6,
				urg		: (q.pkt[q.off+13] & 32) >> 5,
				ack		: (q.pkt[q.off+13] & 16) >> 4,
				psh		: (q.pkt[q.off+13] & 8) >> 3,
				rst		: (q.pkt[q.off+13] & 4) >> 2,
				syn		: (q.pkt[q.off+13] & 2) >> 1,
				fin		: (q.pkt[q.off+13] & 1),
			},
			winsz		: q.pkt.readUInt16BE(q.off+14),
			cksum		: q.pkt.readUInt16BE(q.off+16),
			urg_ptr		: q.pkt.readUInt16BE(q.off+18),
			options		: {},
			data		: {},
		}

		tcp.header_len = tcp.data_off * 4;

		tcp.data.off = q.off + tcp.header_len;
		tcp.data.end = q.pkt.length;
		tcp.data.len = tcp.data.end - tcp.data.off;

		if(tcp.data.len > 0) {
			tcp.data.bytes = q.pkt.slice(tcp.data_off, tcp.data.end);
		}


		q.o.tcp = tcp;
	},

	icmp: function(q) {
		decode.push_path(q, "icmp");
		debug("ICMP");

		var icmp = {
			type		: q.pkt[q.off],
			code		: q.pkt[q.off+1],
			cksum		: q.pkt.readUInt16BE(q.off+2),
			id			: q.pkt.readUInt16BE(q.off+4),
			seq			: q.pkt.readUInt16BE(q.off+6),
		}

		q.o.icmp = icmp;
	},

	ipv6_in_ipv4: function(q) {
		decode.push_path(q, "ipv6_in_ipv4");
		debug("IPV6_IN_IPV4");
	},

	esp: function(q) {
		decode.push_path(q, "esp");
		debug("ESP");
	},

	ah: function(q) {
		decode.push_path(q, "ah");
		debug("AH");
	},

	igmp: function(q) {
		decode.push_path(q, "igmp");
		debug("IGMP");
	},

	ipip: function(q) {
		decode.push_path(q, "ipip");
		debug("IPIP");
	},

	egp: function(q) {
		decode.push_path(q, "egp");
		debug("EGP");
	},

	rsvp: function(q) {
		decode.push_path(q, "rsvp");
		debug("RSVP");
	},

	gre: function(q) {
		decode.push_path(q, "gre");
		debug("GRE");
	},

	icmpv6: function(q) {
		decode.push_path(q, "icmpv6");
		debug("ICMPV6");

		var icmpv6 = {
			type		: q.pkt[q.off],
			code		: q.pkt[q.off+1],
		}

		q.o.icmpv6 = icmpv6;
	},

	_null: function(q) {
		decode.push_path(q,"null");
		debug("NULL");	

		var _null = {
			family	: q.pkt.readUInt16(q.off),
		}

		q.off += 4;

		var idx = nulltypes[_null.family];
		if(idx == undefined) {
			return undefined;
		}

		idx.x(q);
	},

	raw: function(q) {
		decode.push_path(q,"raw");
		debug("RAW");

		var raw = {
		}

		q.off += 0;
		var ret = decode.ipv4(q);
	},


	arp: function(q) {
		decode.push_path(q,"arp");
		debug("ARP");

		var arp = {
			htype		: q.pkt.readUInt16BE(q.off),
			ptype		: q.pkt.readUInt16BE(q.off+2),
			hlen		: q.pkt[q.off+4],
			plen		: q.pkt[q.off+5],
			op			: q.pkt.readUInt16BE(q.off+6),
		}

		if(arp.op == 1) {
			arp.op_desc = "who-has";
		} else if(arp.op == 2) {
			arp.op_desc = "i-have";
		} else {
			arp.op_desc = "unknown";	
		}

		if (arp.hlen === 6 && arp.plen === 4) { 
			arp.sha = unpack.ethernet_addr(q.pkt, q.off+8);
			arp.spa = unpack.ipv4_addr(q.pkt, q.off+14);
			arp.tha = unpack.ethernet_addr(q.pkt, q.off+18);
			arp.tpa = unpack.ipv4_addr(q.pkt, q.off+24);
		}

		q.o.arp = arp;	
	},

	ethernet: function(q) {
		decode.push_path(q,"ethernet");
		debug("ETHERNET");
		
		var ethernet = {
			dst		: unpack.ethernet_addr(q.pkt, q.off+0),
    			src		: unpack.ethernet_addr(q.pkt, q.off+6),
			type	: q.pkt.readUInt16BE(q.off+12),
		}

		var len = 14;

		if(ethernet.type == 0x8100) {
			ethernet.vlan = q.pkt.readUInt16BE(q.off+14);
			ethernet.type = q.pkt.readUInt16BE(q.off+16);
			len = 18;
		}

		q.off += len;


		var idx = ethertypes[ethernet.type];
		if(idx == undefined) {
			return undefined;
		}

		idx.x(q);

		q.o.ehdr = ethernet;
	},

	ieee802_5: function(q) {
		decode.push_path(q,"802.5");
		debug("802_5");
	},

	wireless: function(q) {
		decode.push_path(q,"wifi");
		debug("WIRELESS");
	},

	packet: function(res) {

		var o = {
			path: [res.hdr.if] 
		}

		var q = {
			hdr: res.hdr,
			pkt: res.pkt,
			off: 0,
			o: o,
		}
	
		var idx = datalinks[q.hdr.datalink];
		if(idx == undefined) {
			return undefined;
		}

		idx.x(q);
		debug("o", o, "path", q.path);
		return o;
	},
}











exports.decode = decode;

var datalinks = {
	0: {
		n: "NULL",
		x: decode._null,
	},
	1: {
		n: "ETHERNET",
		x: decode.ethernet,
	},
	6: {
		n: "802.5",
		x: decode.ieee802_5,
	},
	12: {
		n: "RAW",
		x: decode.raw,
	},
	14: {
		n: "RAW",
		x: decode.raw,
	},
	105: {
		n: "WIRELESS",
		x: decode.wireless,
	},
}

var ethertypes = {
	2048: {
		/* 0x800 */
		n: "IPV4",
		x: decode.ipv4,
	},
	2054: {
		/* 0x806 */
		n: "ARP",
		x: decode.arp,
	},
	34525: {
		/* 0x86dd */
		n: "IPV6",
		x: decode.ipv6,
	},
}


var nulltypes = {
	2: {
		n: "IPV4 PF_INET",
		x: decode.ipv4,
	},	
	10: {
		n: "IPV6 PF_INET6",
		x: decode.ipv6,
	},
}


var layer3_4 = {
	0: {
		n: "IP",
		x: decode.ipv4,
	},
	1: {
		n: "ICMP",
		x: decode.icmp,
	},
	2: {
		n: "IGMP",
		x: decode.igmp,
	},
	4: {
		n: "IPIP",
		x: decode.ipip,
	},
	6: {
		n: "TCP",
		x: decode.tcp,
	},
	8: {
		n: "EGP",
		x: decode.egp,
	},
	17: {
		n: "UDP",
		x: decode.udp,
	},
	41: {
		n: "IPV6_IN_IPV4",
		x: decode.ipv6_in_ipv4,
	},
	43: {
		n: "IPV6",
		x: decode.ipv6,
	},
	46: {
		n: "RSVP",
		x: decode.rsvp,
	},
	47: {
		n: "GRE",
		x: decode.gre,
	},
	50: {
		n: "ESP",
		x: decode.esp,
	},
	51: {
		n: "AH",
		x: decode.ah,
	},
	58: {
		n: "ICMPv6",
		x: decode.icmpv6,
	},
}





var decodeit = function(res) {
	return decode.packet(res);
}
exports.decodeit = decodeit;
