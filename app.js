'use strict'
var cfg = require('./config.json');
const dgram = require('dgram');
const server = dgram.createSocket('udp4');
var sip = require('sip');
var redis = require("redis");
var cache = redis.createClient();

const Client = require('pg').Client;
const client = new Client(cfg);
client.connect((err) => {
	if (err) {
		console.error('connection error', err.stack)
	} else {
		console.log('db connected');

	}
});

var remip = '127.0.0.1'; //test server IP to send to forward the message
var remport = '5061'; //test server port to send to forward the message

var dialogTrash = [];
var dialogTrashTimer = setInterval(dialogTrashExecuter, 2000);
/* CRYPTO */
var crypto = require('crypto');
var algorithm = 'aes-256-ctr';
var password = 'gHH53cx!qK86ggnV#';
/* END CRYPTO */

server.on('error', (err) => {
	console.log(`server error:\n${err.stack}`);
	server.close();
});

server.on('message', (msg, rinfo) => {
	checkMessage(msg, rinfo);
});

server.on('listening', () => {
	const address = server.address();
	console.log(`server listening ${address.address}:${address.port}`);
});

server.bind(5060);

function checkMessage(msg, rinfo) {
	let message = sip.parse(msg);
	//check for undefined
	if (typeof message === 'undefined') return;
	//console.log('newMsg',message);

	if (message.method) {
		console.log(message.method + ' ' + message.headers.from.uri + '->' + message.headers.to.uri);
		switch (message.method) {
			case 'REGISTER':
				checkREGISTER(message, rinfo);
				break;

			case 'OPTIONS':
				checkOPTIONS(message, rinfo);
				break;

			case 'INVITE':
				checkINVITE(message, rinfo);
				break;

			default:
				checkGENERIC(message, rinfo);
				break;
		}
	} else if (message.status) {
		checkRESPONSE(message, rinfo);
	}

}

function checkREGISTER(msg, rinfo) {
	console.log('checkREGISTER');
	let msgid = msg.headers['call-id'] + '-' + msg.headers.cseq.seq + '-' + msg.headers.cseq.method;
	//console.log('uri', msg.headers.via);
	cache.hsetnx('requests', msgid, JSON.stringify({
		ts: new Date().getTime(),
		msg: msg
	}), function () {
		try {
			//URI (must be *.sipflare.com)
			let reguri = sip.parseUri(msg.uri);
			console.log('uri host ', reguri.host);
			getSubdomain(reguri.host,function(err,data){
				try {
					console.log(data);
					if (data.rowCount > 0) {
						let tmpserver;
						let dataRow = data.rows[0].row_to_json;
						for (var i = 0; i < dataRow.options.servers.length; i++) {
							var entry = dataRow.options.servers[i];
							console.log('entry', entry);
							if (tmpserver) {
								if (entry.last > tmpserver.last) {
									tmpserver = entry;
								}
							} else {
								tmpserver = entry;
							}
						}
						if (tmpserver) {
							//VIA
							msg.headers.via[0].host = cfg.listen_ip;
							msg.headers.via[0].port = cfg.listen_port;
							// CONTACT 
							let contacturi = sip.parseUri(msg.headers.contact[0].uri);
							contacturi.host = cfg.listen_ip;
							contacturi.port = cfg.listen_port;
							contacturi.params.sipflare = encrypt(rinfo.address + ':' + rinfo.port);
							//console.log('uri',contacturi);
							msg.headers.contact[0].uri = sip.stringifyUri(contacturi);

							sendMessage(sip.stringify(msg), tmpserver.server, tmpserver.port);
						}
					} else {
						try {
							sendMessage(sip.stringify(sip.makeResponse(msg, 403, 'Forbidden')), msg.headers.via[0].host, msg.headers.via[0].port);
						} catch (e2) {}
					}
				} catch (e1) {
					console.log('EX checkREGISTER', e1);
				}
			});
		} catch (e) {
			console.log('EX checkREGISTER', e);
		}
	});

}

function checkOPTIONS(msg, rinfo) {
	console.log('checkOPTIONS');
	let msgid = msg.headers['call-id'] + '-' + msg.headers.cseq.seq + '-' + msg.headers.cseq.method;
	//console.log('uri', msg.headers.via);
	cache.hsetnx('requests', msgid, JSON.stringify({
		ts: new Date().getTime(),
		msg: msg
	}), function () {
		//VIA
		msg.headers.via[0].host = cfg.listen_ip;
		msg.headers.via[0].port = cfg.listen_port;
		// CONTACT 
		if (msg.headers.contact) {
			let contacturi = sip.parseUri(msg.headers.contact[0].uri);
			contacturi.host = cfg.listen_ip;
			contacturi.port = cfg.listen_port;
			msg.headers.contact[0].uri = sip.stringifyUri(contacturi);
		}

		let tmpip = remip;
		let tmpport = remport;

		let touri = sip.parseUri(msg.headers.to.uri);
		//check for sipflare
		if (touri.params.sipflare) {
			//console.log('SIPFLARE recv');
			try {
				let tmpdecr = decrypt(touri.params.sipflare);
				if (tmpdecr.indexOf(':') > -1) {
					let tmpaddr = tmpdecr.split(':');
					if (tmpaddr.length === 2) {
						tmpip = tmpaddr[0];
						tmpport = tmpaddr[1];
						//console.log('new addr ', tmpip,tmpport);
						delete touri.params.sipflare;
						msg.headers.to.uri = sip.stringifyUri(touri);
					}
				}
			} catch (e) {}
		}
		sendMessage(sip.stringify(msg), tmpip, tmpport);
	});

}

function checkINVITE(msg, rinfo) {
	console.log('checkINVITE');
	let msgid = msg.headers['call-id'] + '-' + msg.headers.cseq.seq + '-' + msg.headers.cseq.method;
	//console.log('uri', msg.headers.via);
	cache.hsetnx('requests', msgid, JSON.stringify({
		ts: new Date().getTime(),
		msg: msg
	}), function () {
		//VIA
		msg.headers.via[0].host = cfg.listen_ip;
		msg.headers.via[0].port = cfg.listen_port;
		// CONTACT 
		let contacturi = sip.parseUri(msg.headers.contact[0].uri);
		contacturi.host = cfg.listen_ip;
		contacturi.port = cfg.listen_port;

		let tmpip = remip;
		let tmpport = remport;

		let touri = sip.parseUri(msg.headers.to.uri);
		//check for sipflare
		if (touri.params.sipflare) {
			//console.log('SIPFLARE recv');
			try {
				let tmpdecr = decrypt(touri.params.sipflare);
				if (tmpdecr.indexOf(':') > -1) {
					let tmpaddr = tmpdecr.split(':');
					if (tmpaddr.length === 2) {
						tmpip = tmpaddr[0];
						tmpport = tmpaddr[1];
						//console.log('new addr ', tmpip,tmpport);
						delete touri.params.sipflare;
						msg.headers.to.uri = sip.stringifyUri(touri);
					}
				}
			} catch (e) {}
		}

		msg.headers.contact[0].uri = sip.stringifyUri(contacturi);

		sendMessage(sip.stringify(msg), tmpip, tmpport);
	});

}

function checkGENERIC(msg, rinfo) {
	console.log('checkGENERIC');
	let msgid = msg.headers['call-id'] + '-' + msg.headers.cseq.seq + '-' + msg.headers.cseq.method;
	//console.log('uri', msg.headers.via);
	cache.hsetnx('requests', msgid, JSON.stringify({
		ts: new Date().getTime(),
		msg: msg
	}), function () {
		//VIA
		msg.headers.via[0].host = cfg.listen_ip;
		msg.headers.via[0].port = cfg.listen_port;
		// CONTACT 
		if (msg.headers.contact) {
			let contacturi = sip.parseUri(msg.headers.contact[0].uri);
			contacturi.host = cfg.listen_ip;
			contacturi.port = cfg.listen_port;
			msg.headers.contact[0].uri = sip.stringifyUri(contacturi);
		}

		let tmpip = remip;
		let tmpport = remport;

		let touri = sip.parseUri(msg.headers.to.uri);
		//check for sipflare
		if (touri.params.sipflare) {
			//console.log('SIPFLARE recv');
			try {
				let tmpdecr = decrypt(touri.params.sipflare);
				if (tmpdecr.indexOf(':') > -1) {
					let tmpaddr = tmpdecr.split(':');
					if (tmpaddr.length === 2) {
						tmpip = tmpaddr[0];
						tmpport = tmpaddr[1];
						//console.log('new addr ', tmpip,tmpport);
						delete touri.params.sipflare;
						msg.headers.to.uri = sip.stringifyUri(touri);
					}
				}
			} catch (e) {}
		}
		sendMessage(sip.stringify(msg), tmpip, tmpport);
	});

}

function checkRESPONSE(msg, rinfo) {
	let msgid = msg.headers['call-id'] + '-' + msg.headers.cseq.seq + '-' + msg.headers.cseq.method;
	cache.hget('requests', msgid, function (err, origmsg) {

		try {
			let reqmsg = JSON.parse(origmsg);
			//REPLACE VIA
			msg.headers.via[0].host = cfg.listen_ip;
			msg.headers.via[0].port = cfg.listen_port;

			//let contacturi = sip.parseUri(reqmsg.msg.headers.contact[0].uri);	
			// CONTACT 
			if (msg.headers.contact) {
				let tmpcontacturi = sip.parseUri(msg.headers.contact[0].uri);
				tmpcontacturi.host = cfg.listen_ip;
				tmpcontacturi.port = cfg.listen_port;
				msg.headers.contact[0].uri = sip.stringifyUri(tmpcontacturi);
			}

			console.log('sendMsg', msg.status, reqmsg.msg.headers.via[0].host, reqmsg.msg.headers.via[0].port);
			sendMessage(sip.stringify(msg), reqmsg.msg.headers.via[0].host, reqmsg.msg.headers.via[0].port);
			//sendMessage(sip.stringify(msg),contacturi.host,contacturi.port);
			dialogTrash.push({
				ts: (new Date().getTime() + 10000),
				dlgid: msgid
			});
		} catch (e) {}
	});
}

function sendMessage(msg, address, port) {
	//console.log('sendMessage',address,port,msg);
	server.send(msg, port, address, (err) => {
		//console.log('sendMessage err',err);
	});
}

function dialogTrashExecuter() {
	for (let x = 0; x < dialogTrash.length; x++) {
		let trashobj = dialogTrash[x];
		if (trashobj) {
			if (new Date().getTime() > trashobj.ts) {
				dialogTrash.splice(x, 1);
				cache.hexists('requests', trashobj.dlgid, function (exists) {
					if (exists) {
						cache.hdel('requests', trashobj.dlgid, function () {});
						console.log('[TRASH] transaction ' + trashobj.dlgid + ' removed');
					}
				});
			}
		}
	}
}

function getSubdomain(subdomain, callback) {
	let qry = 'select row_to_json(t) from (select managed,options from dns_domains where domain = $1) t';
	let param = [subdomain];
	client.query(qry, param, (err, res) => {
		callback(err, res);
	});
}

/* CRYPTO FUNCTIONS */
function encrypt(text) {
	var cipher = crypto.createCipher(algorithm, password)
	var crypted = cipher.update(text, 'utf8', 'hex')
	crypted += cipher.final('hex');
	return crypted;
}

function decrypt(text) {
	var decipher = crypto.createDecipher(algorithm, password)
	var dec = decipher.update(text, 'hex', 'utf8')
	dec += decipher.final('utf8');
	return dec;
}
