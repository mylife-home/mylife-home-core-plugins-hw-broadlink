// ---


'use strict'
const _blEvnt = 'brl:';
const crypto = require('crypto');
var BLK = {};
BLK.Commands = {
    Auth        : [0x65,0x3e9],
    TogglePower : [0x6a,0x3ee]
};

BLK.Auth = {
    Request : (target) => {
        var res = {
            command : BLK.Commands.Auth,
            target : target,
            isEncrypted : true
        };
if(!target) return res;
var buffer = Buffer.alloc(80);
        var key = crypto.randomBytes(16);//target.key || BLK.key;
        key.copy(buffer,4);                         //  0x4     : Shared key (16 bytes)

        //buffer.writeUInt8(0x1,30); //                 0x1e    : 0x1
        buffer.writeUInt8(0x1,45); //                   0x2d    : 0x1
buffer.write('Khone alone',48, 'ascii'); //     0x30    : Device name
        res.payload = buffer;

        return res;
    },
Response : (buffer, target) => {
        var res = { };
        var data = _decryptPayload(buffer, BLK.key);
var key = Buffer.alloc(16);
        data.copy(key,0,4,20); //                               0x4     : key in payload
var id = data.readInt32LE(0); //                        0x0     : device id in payload
res.key = key;
        res.id = id;
        res.target = target; //TODO do not need to return res, return target itself
        console.log('INFO | %s (#%s) key is %s',target.kind, res.id, res.key.toString('hex'));
        return res;
    }
};
BLK.TogglePower = {
    Request : (target, state) => {
        var res = {
            command : BLK.Commands.TogglePower,
            target : target,
            isEncrypted : true
        };
if(target && target.id && target.key){
            var buffer = Buffer.alloc(16);
            buffer.writeUInt8((state != null)?2:1,0); //          0x0 : toggle->value=2, check->value=1
            buffer.writeUInt8(state?1:0,4); //                     0x4 : 1: on, 2: off
            res.payload = buffer;
        }
        return res;
    },
Response : (buffer, target) => {
        var res = {
            target : target
        };
        var err = buffer.readUInt16LE(34); //           0x22 : Error
        if(err === 0) {
            var data = _decryptPayload(buffer,target.key);
            res.state = data.readUInt8(4)?'ON':'OFF';// 0x4 : State
            if(data.length > 16) {
                //this is info message
//TODO: parse and learn
                console.log('==>',data.toString('hex'));
             }
} else {
            console.log('ERR | Error %s getting device %s power state', err, target.id);
        }
        return res;
}
};
BLK.getPacket = (message, deviceId = 0x7D00 ,currentCID = [0xa5,0xaa,0x55,0x5a,0xa5,0xaa,0x55,0x0]) =>{
    if(!message.payload) message.payload = Buffer.alloc(0);
    var isBroadcast = !message.target || !message.target.ip  || message.target.ip == '255.255.255.255' || message.target.ip == '224.0.0.251';
    //QUIC header
    if(isBroadcast || message.isPublic){
        var packet = Buffer.alloc(8); //0x8 padding, Public flag = 0x0
        //multicast - PKN:0
        //merge payload right away
        if(message.payload.length < 40){  // minimum payload length
            var filler = Buffer.alloc(40 - message.payload.length);
            message.payload = Buffer.concat([message.payload,filler]);
        }
        packet = Buffer.concat([packet,message.payload]);
    } else {
        var packet = Buffer.alloc(56); //0x38 total custom header length
packet.writeUInt8(0x5a,0); //Version:0, Reset:Yes, CID:0x2,Packet #1, Multipath:Yes
        var cid = Buffer.from(message.target.CID || currentCID);
        cid.copy(packet,1);
        //tag:0x0, tag #:0x0, padding: 0
    }
packet.writeUInt16LE(deviceId,36); //                               0x24  : Device ID
    packet.writeUInt8(message.command[0],38); //                        0x26  : Command

    if(!isBroadcast && !message.isPublic) {
        BLK.mgs = BLK.mgs || 0;
        packet.writeUInt16LE(BLK.mgs++ & 0xFFFF, 40); //      0x28  : Send Counter

        if(message.target.mac) {
var m = message.target.mac.split(':').reverse();
            var offset = 42; //                                         0x2a  : MAC
            for(var i=0;i<m.length;i++){
                packet.writeUInt8(parseInt(m[i],16),offset++);
            }
        }
        if(message.target.id){
            packet.writeUInt32LE(48);             //        0x30  : Device ID
        }
if(message.payload.length > 0) {
            var cs = _cs(message.payload);
            packet.writeUInt16LE(cs,52); //                               0x34  : Header Checksum
        }
if(message.isEncrypted){

            BLK.key = Buffer.from([0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]);
            BLK.iv = Buffer.from([0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58]);
            var key = message.target.key || BLK.key;
            var cipher = crypto.createCipheriv('aes-128-cbc', key, BLK.iv);
            cipher.setAutoPadding(false);
            message.payload = Buffer.concat([cipher.update(message.payload),cipher.final()]);
        }

        packet = Buffer.concat([packet,message.payload]);
    }
var cs = _cs(packet);
    packet.writeUInt16LE(cs, 32); //                                        0x20   : Full checksum
return packet;
}
var _decryptPayload = (buffer, key) => {
    var data = Buffer.alloc(buffer.length - 56); //         0x38    : Encrypted payload
    buffer.copy(data,0, 56, buffer.length);

    var decipher = crypto.createDecipheriv('aes-128-cbc',key,BLK.iv);
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(data) , decipher.final()]);
};
var _readMac = (buffer,start) => {
    var mac = [];
    for(var i=start;i<start+6;i++){
        mac.push(buffer.readUInt8(i).toString(16));
    }
    return mac.reverse().join(':');
};
var _cs = (buffer) => (0xbeaf + Array.prototype.slice.call(buffer,0).reduce((p,c)=> (p+c))) & 0xffff;
//TODO: Maybe i will call it translate? :)
var _readType = (buffer,start) => {
    var type = buffer.toString('utf8',start,buffer.length);
    if(type.match('智能插座').length > 0) return 'SMART SOCKET';
    else return 'UNDEFINED';
};
var _readDeviceType = (buffer) => {
    var type = buffer.readUInt16LE(36);
    switch(type){
        case 0: return 'SP1'; break;
        case 0x2711: return 'SP2'; break;
        case 0x2719:
        case 0x7919:
        case 0x271a:
        case 0x791a: return 'Honeywell SP2'; break;
        case 0x2720: return 'SPMini'; break;
        case 0x753e: return 'SP3'; break;
        case 0x2728: return 'SPMini2'; break;
        case 0x2733:
        case 0x273e: return 'SPMini OEM'; break;
        case 0x2736: return 'SPMiniPlus'; break;
        case 0x2712: return 'RM2'; break;
        case 0x2737: return 'RM Mini'; break;
        case 0x273d: return 'RM Pro Phicomm'; break;
        case 0x2783: return 'RM2 Home Plus'; break;
        case 0x277c: return 'RM2 Home Plus GDT'; break;
        case 0x272a: return 'RM2 Pro Plus'; break;
        case 0x2787: return 'RM2 Pro Plus2'; break;
        case 0x278b: return 'RM2 Pro Plus BL'; break;
        case 0x278f: return 'RM Mini Shate'; break;
        case 0x2714: return 'A1'; break;
        case 0x4EB5: return 'MP1'; break;
        default:
            if(type >= 0x7530 & type <= 0x7918) return 'SPMini2 OEM';
            else return 'Unknown';
        break;
    }
}
BLK.getName = function(value) {
  return Object.keys(BLK.Commands).find(key => Array.isArray(value) ? BLK.Commands[key] === value : BLK.Commands[key].includes(value));
};
BLK.get = function(value) {
  var m = BLK.getName(value);
  if(!m) return null;
  return this[m];
};
BLK.getTrigger = function(msg) {
    var m = BLK.get(msg.command);
    if(m){
        var n = BLK.getName(msg.command);
        return _blEvnt+n;
    }
    return null;
};
BLK.parse = function(buffer, targets){
    if(buffer.length < 48){
        console.log('ERR | Response message is too short (%d bytes)',buffer.length);
        return null;
    }
    var cs = buffer.readUInt16LE(32);
    buffer.writeUInt16LE(0x0,32);
    if(_cs(buffer) != cs){
        console.log('ERR | Wrong incoming message format : ',JSON.stringify(buffer));
        return null;
    }
//header
    /*if(buffer.readUInt8(0) & 2){ //this is public reset
        //hack to workout JS bug!
        var cid = [];
        for(var i=1;i<=8;i++) {
            cid.push(buffer[i]);
        }

        //attach it to device
    }*/
    var command = buffer.readUInt16LE(38);
    var device = _readDeviceType(buffer);
    var srs = _readMac(buffer,42);
var msg = BLK.get(command);
    if(!msg){
        console.log('TODO | Unknown incoming message 0x%s',command.toString(16));
        return null;
    }
var evt = BLK.getTrigger(msg.Request());
    var target = targets.find(t=>t.id === evt)
    var res = msg.Response(buffer, target?target.target:null);
    res.event = evt;
    res.name = BLK.getName(command);
    res.srs = srs;
    res.kind = device;
    return res;
};
module.exports = BLK;

// -----------

var util = require('util');
let EventEmitter = require('events');
let dgram = require('dgram');
let os = require('os');
let crypto = require('crypto');

var Broadlink = module.exports = function() {
    EventEmitter.call(this);
    this.devices = {};
}
util.inherits(Broadlink, EventEmitter);


Broadlink.prototype.genDevice = function(devtype, host, mac) {
    var dev;
    if (devtype == 0) { // SP1
        dev = new device(host, mac);
        dev.sp1();
        return dev;
    } else if (devtype == 0x2711) { // SP2
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    } else if (devtype == 0x2719 || devtype == 0x7919 || devtype == 0x271a || devtype == 0x791a) { // Honeywell SP2
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    } else if (devtype == 0x2720) { // SPMini
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    } else if (devtype == 0x753e) { // SP3
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    } else if (devtype == 0x2728) { // SPMini2
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    } else if (devtype == 0x2733 || devtype == 0x273e) { // OEM branded SPMini Contros
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    } else if (devtype >= 0x7530 && devtype <= 0x7918) { // OEM branded SPMini2
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    } else if (devtype == 0x2736) { // SPMiniPlus
        dev = new device(host, mac);
        dev.sp2();
        return dev;
    }
    /*else if (devtype == 0x2712) { // RM2
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x2737) { // RM Mini
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x273d) { // RM Pro Phicomm
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x2783) { // RM2 Home Plus
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x277c) { // RM2 Home Plus GDT
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x272a) { // RM2 Pro Plus
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x2787) { // RM2 Pro Plus2
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x278b) { // RM2 Pro Plus BL
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } else if (devtype == 0x278f) { // RM Mini Shate
           dev = new device(host, mac);
           dev.rm();
           return dev;
       } */
    else if (devtype == 0x2714) { // A1
        dev = new device(host, mac);
        dev.a1();
        return dev;
    } else if (devtype == 0x4EB5) { // MP1
        dev = new device(host, mac);
        dev.mp1();
        return dev;
    } else {
        //console.log("unknown device found... dev_type: " + devtype.toString(16) + " @ " + host.address);
        //dev = new device(host, mac);
        //dev.device();
        return null;
    }
}

Broadlink.prototype.discover = function() {
    self = this;
    var interfaces = os.networkInterfaces();
    var addresses = [];
    for (var k in interfaces) {
        for (var k2 in interfaces[k]) {
            var address = interfaces[k][k2];
            if (address.family === 'IPv4' && !address.internal) {
                addresses.push(address.address);
            }
        }
    }
    var address = addresses[0].split('.');
    var cs = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    cs.on('listening', function() {
        cs.setBroadcast(true);

        var port = cs.address().port;
        var now = new Date();
        var starttime = now.getTime();

        var timezone = now.getTimezoneOffset() / -3600;
        var packet = Buffer.alloc(0x30, 0);

        var year = now.getYear();

        if (timezone < 0) {
            packet[0x08] = 0xff + timezone - 1;
            packet[0x09] = 0xff;
            packet[0x0a] = 0xff;
            packet[0x0b] = 0xff;
        } else {
            packet[0x08] = timezone;
            packet[0x09] = 0;
            packet[0x0a] = 0;
            packet[0x0b] = 0;
        }
        packet[0x0c] = year & 0xff;
        packet[0x0d] = year >> 8;
        packet[0x0e] = now.getMinutes();
        packet[0x0f] = now.getHours();
        var subyear = year % 100;
        packet[0x10] = subyear;
        packet[0x11] = now.getDay();
        packet[0x12] = now.getDate();
        packet[0x13] = now.getMonth();
        packet[0x18] = parseInt(address[0]);
        packet[0x19] = parseInt(address[1]);
        packet[0x1a] = parseInt(address[2]);
        packet[0x1b] = parseInt(address[3]);
        packet[0x1c] = port & 0xff;
        packet[0x1d] = port >> 8;
        packet[0x26] = 6;
        var checksum = 0xbeaf;

        for (var i = 0; i < packet.length; i++) {
            checksum += packet[i];
        }
        checksum = checksum & 0xffff;
        packet[0x20] = checksum & 0xff;
        packet[0x21] = checksum >> 8;

        cs.sendto(packet, 0, packet.length, 80, '255.255.255.255');

    });

    cs.on("message", (msg, rinfo) => {
        var host = rinfo;

        var mac = Buffer.alloc(6, 0);
        msg.copy(mac, 0x00, 0x3F);
        msg.copy(mac, 0x01, 0x3E);
        msg.copy(mac, 0x02, 0x3D);
        msg.copy(mac, 0x03, 0x3C);
        msg.copy(mac, 0x04, 0x3B);
        msg.copy(mac, 0x05, 0x3A);

        var devtype = msg[0x34] | msg[0x35] << 8;
        if (!this.devices) {
            this.devices = {};
        }

        if (!this.devices[mac]) {
            var dev = this.genDevice(devtype, host, mac);
            if (dev) {
                this.devices[mac] = dev;
                dev.on("deviceReady", () => { this.emit("deviceReady", dev); });
                dev.auth();
            }
        }
    });

    cs.on('close', function() {
        //console.log('===Server Closed');
    });

    cs.bind();

    setTimeout(function() {
        cs.close();
    }, 300);
}

function device(host, mac, timeout = 10) {
    this.host = host;
    this.mac = mac;
    this.emitter = new EventEmitter();

    this.on = this.emitter.on;
    this.emit = this.emitter.emit;
    this.removeListener = this.emitter.removeListener;

    this.timeout = timeout;
    this.count = Math.random() & 0xffff;
    this.key = new Buffer([0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]);
    this.iv = new Buffer([0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58]);
    this.id = new Buffer([0, 0, 0, 0]);
    this.cs = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.cs.on('listening', function() {
        //this.cs.setBroadcast(true);
    });
    this.cs.on("message", (response, rinfo) => {
        var enc_payload = Buffer.alloc(response.length - 0x38, 0);
        response.copy(enc_payload, 0, 0x38);

        var decipher = crypto.createDecipheriv('aes-128-cbc', this.key, this.iv);
        decipher.setAutoPadding(false);
        var payload = decipher.update(enc_payload);
        var p2 = decipher.final();
        if (p2) {
            payload = Buffer.concat([payload, p2]);
        }

        if (!payload) {
            return false;
        }

        var command = response[0x26];
        var err = response[0x22] | (response[0x23] << 8);

        if (err != 0) return;

        if (command == 0xe9) {
            this.key = Buffer.alloc(0x10, 0);
            payload.copy(this.key, 0, 0x04, 0x14);

            this.id = Buffer.alloc(0x04, 0);
            payload.copy(this.id, 0, 0x00, 0x04);
            this.emit("deviceReady");
        } else if (command == 0xee) {
            this.emit("payload", err, payload);
        }

    });
    this.cs.bind();
    this.type = "Unknown";

}

device.prototype.auth = function() {
    var payload = Buffer.alloc(0x50, 0);
    payload[0x04] = 0x31;
    payload[0x05] = 0x31;
    payload[0x06] = 0x31;
    payload[0x07] = 0x31;
    payload[0x08] = 0x31;
    payload[0x09] = 0x31;
    payload[0x0a] = 0x31;
    payload[0x0b] = 0x31;
    payload[0x0c] = 0x31;
    payload[0x0d] = 0x31;
    payload[0x0e] = 0x31;
    payload[0x0f] = 0x31;
    payload[0x10] = 0x31;
    payload[0x11] = 0x31;
    payload[0x12] = 0x31;
    payload[0x1e] = 0x01;
    payload[0x2d] = 0x01;
    payload[0x30] = 'T'.charCodeAt(0);
    payload[0x31] = 'e'.charCodeAt(0);
    payload[0x32] = 's'.charCodeAt(0);
    payload[0x33] = 't'.charCodeAt(0);
    payload[0x34] = ' '.charCodeAt(0);
    payload[0x35] = ' '.charCodeAt(0);
    payload[0x36] = '1'.charCodeAt(0);

    this.sendPacket(0x65, payload);

}

device.prototype.exit = function() {
    var self = this;
    setTimeout(function() {
        self.cs.close();
    }, 500);
}

device.prototype.getType = function() {
    return this.type;
}

device.prototype.sendPacket = function(command, payload) {
    this.count = (this.count + 1) & 0xffff;
    var packet = Buffer.alloc(0x38, 0);
    packet[0x00] = 0x5a;
    packet[0x01] = 0xa5;
    packet[0x02] = 0xaa;
    packet[0x03] = 0x55;
    packet[0x04] = 0x5a;
    packet[0x05] = 0xa5;
    packet[0x06] = 0xaa;
    packet[0x07] = 0x55;
    packet[0x24] = 0x2a;
    packet[0x25] = 0x27;
    packet[0x26] = command;
    packet[0x28] = this.count & 0xff;
    packet[0x29] = this.count >> 8;
    packet[0x2a] = this.mac[0];
    packet[0x2b] = this.mac[1];
    packet[0x2c] = this.mac[2];
    packet[0x2d] = this.mac[3];
    packet[0x2e] = this.mac[4];
    packet[0x2f] = this.mac[5];
    packet[0x30] = this.id[0];
    packet[0x31] = this.id[1];
    packet[0x32] = this.id[2];
    packet[0x33] = this.id[3];

    var checksum = 0xbeaf;
    for (var i = 0; i < payload.length; i++) {
        checksum += payload[i];
        checksum = checksum & 0xffff;
    }

    var cipher = crypto.createCipheriv('aes-128-cbc', this.key, this.iv);
    payload = cipher.update(payload);
    var p2 = cipher.final();

    packet[0x34] = checksum & 0xff;
    packet[0x35] = checksum >> 8;

    packet = Buffer.concat([packet, payload]);

    checksum = 0xbeaf;
    for (var i = 0; i < packet.length; i++) {
        checksum += packet[i];
        checksum = checksum & 0xffff;
    }
    packet[0x20] = checksum & 0xff;
    packet[0x21] = checksum >> 8;
    //console.log("dev send packet to " + this.host.address + ":" + this.host.port);
    this.cs.sendto(packet, 0, packet.length, this.host.port, this.host.address);
}

device.prototype.mp1 = function() {
    this.type = "MP1";

    this.set_power = function(sid, state) {
        //"""Sets the power state of the smart power strip."""
        var sid_mask = 0x01 << (sid - 1);
        var packet = Buffer.alloc(16, 0);
        packet[0x00] = 0x0d;
        packet[0x02] = 0xa5;
        packet[0x03] = 0xa5;
        packet[0x04] = 0x5a;
        packet[0x05] = 0x5a;
        packet[0x06] = 0xb2 + (state ? (sid_mask << 1) : sid_mask);
        packet[0x07] = 0xc0;
        packet[0x08] = 0x02;
        packet[0x0a] = 0x03;
        packet[0x0d] = sid_mask;
        packet[0x0e] = state ? sid_mask : 0;

        this.sendPacket(0x6a, packet);
    }

    this.check_power = function() {
        //"""Returns the power state of the smart power strip in raw format."""
        var packet = Buffer.alloc(16, 0);
        packet[0x00] = 0x0a;
        packet[0x02] = 0xa5;
        packet[0x03] = 0xa5;
        packet[0x04] = 0x5a;
        packet[0x05] = 0x5a;
        packet[0x06] = 0xae;
        packet[0x07] = 0xc0;
        packet[0x08] = 0x01;

        this.sendPacket(0x6a, packet);
    }

    this.on("payload", (err, payload) => {
        var param = payload[0];
        switch (param) {
            case 1:
                console.log("case 1 -");
                break;
            case 2:
                console.log("case 2 -");
                break;
            case 3:
                console.log("case 3 -");
                break;
            case 4:
                console.log("case 4 -");
                break;
            case 14:
                var s1 = Boolean(payload[0x0e] & 0x01);
                var s2 = Boolean(payload[0x0e] & 0x02);
                var s3 = Boolean(payload[0x0e] & 0x04);
                var s4 = Boolean(payload[0x0e] & 0x08);
                this.emit("mp_power", [s1, s2, s3, s4]);
                break;
            default:
                console.log("case default - " + param);
                break;
        }
    });
}


device.prototype.sp1 = function() {
    this.type = "SP1";
    this.set_power = function(state) {
        var packet = Buffer.alloc(4, 4);
        packet[0] = state;
        this.sendPacket(0x66, packet);
    }
}



device.prototype.sp2 = function() {
    var self = this;
    this.type = "SP2";
    this.set_power = function(state) {
        //"""Sets the power state of the smart plug."""
        var packet = Buffer.alloc(16, 0);
        packet[0] = 2;
        packet[4] = state ? 1 : 0;
        this.sendPacket(0x6a, packet);

    }

    this.check_power = function() {
        //"""Returns the power state of the smart plug."""
        var packet = Buffer.alloc(16, 0);
        packet[0] = 1;
        this.sendPacket(0x6a, packet);

    }

    this.on("payload", (err, payload) => {
        var param = payload[0];
        switch (param) {
            case 1: //get from check_power
                var pwr = Boolean(payload[0x4]);
                this.emit("power", pwr);
                break;
            case 3:
                console.log('case 3');
                break;
            case 4:
                console.log('case 4');
                break;
        }

    });


}

device.prototype.a1 = function() {
    this.type = "A1";
    this.check_sensors = function() {
        var packet = Buffer.alloc(16, 0);
        packet[0] = 1;
        this.sendPacket(0x6a, packet);
        /*
           err = response[0x22] | (response[0x23] << 8);
           if(err == 0){
           data = {};
           aes = AES.new(bytes(this.key), AES.MODE_CBC, bytes(self.iv));
           payload = aes.decrypt(bytes(response[0x38:]));
           if(type(payload[0x4]) == int){
           data['temperature'] = (payload[0x4] * 10 + payload[0x5]) / 10.0;
           data['humidity'] = (payload[0x6] * 10 + payload[0x7]) / 10.0;
           light = payload[0x8];
           air_quality = payload[0x0a];
           noise = payload[0xc];
           }else{
           data['temperature'] = (ord(payload[0x4]) * 10 + ord(payload[0x5])) / 10.0;
           data['humidity'] = (ord(payload[0x6]) * 10 + ord(payload[0x7])) / 10.0;
           light = ord(payload[0x8]);
           air_quality = ord(payload[0x0a]);
           noise = ord(payload[0xc]);
           }
           if(light == 0){
           data['light'] = 'dark';
           }else if(light == 1){
           data['light'] = 'dim';
           }else if(light == 2){
           data['light'] = 'normal';
           }else if(light == 3){
           data['light'] = 'bright';
           }else{
           data['light'] = 'unknown';
           }
           if(air_quality == 0){
           data['air_quality'] = 'excellent';
           }else if(air_quality == 1){
           data['air_quality'] = 'good';
           }else if(air_quality == 2){
           data['air_quality'] = 'normal';
           }else if(air_quality == 3){
           data['air_quality'] = 'bad';
           }else{
           data['air_quality'] = 'unknown';
           }
           if(noise == 0){
           data['noise'] = 'quiet';
           }else if(noise == 1){
           data['noise'] = 'normal';
           }else if(noise == 2){
           data['noise'] = 'noisy';
           }else{
           data['noise'] = 'unknown';
           }
           return data;
           }
           */
    }

    this.check_sensors_raw = function() {
        var packet = Buffer.alloc(16, 0);
        packet[0] = 1;
        this.sendPacket(0x6a, packet);
        /*
           err = response[0x22] | (response[0x23] << 8);
           if(err == 0){
           data = {};
           aes = AES.new(bytes(this.key), AES.MODE_CBC, bytes(self.iv));
           payload = aes.decrypt(bytes(response[0x38:]));
           if(type(payload[0x4]) == int){
           data['temperature'] = (payload[0x4] * 10 + payload[0x5]) / 10.0;
           data['humidity'] = (payload[0x6] * 10 + payload[0x7]) / 10.0;
           data['light'] = payload[0x8];
           data['air_quality'] = payload[0x0a];
           data['noise'] = payload[0xc];
           }else{
           data['temperature'] = (ord(payload[0x4]) * 10 + ord(payload[0x5])) / 10.0;
           data['humidity'] = (ord(payload[0x6]) * 10 + ord(payload[0x7])) / 10.0;
           data['light'] = ord(payload[0x8]);
           data['air_quality'] = ord(payload[0x0a]);
           data['noise'] = ord(payload[0xc]);
           }
           return data;
           }
           */
    }
}


device.prototype.rm = function() {
    this.type = "RM2";
    this.checkData = function() {
        var packet = Buffer.alloc(16, 0);
        packet[0] = 4;
        this.sendPacket(0x6a, packet);
    }

    this.sendData = function(data) {
        packet = new Buffer([0x02, 0x00, 0x00, 0x00]);
        packet = Buffer.concat([packet, data]);
        this.sendPacket(0x6a, packet);
    }

    this.enterLearning = function() {
        var packet = Buffer.alloc(16, 0);
        packet[0] = 3;
        this.sendPacket(0x6a, packet);
    }

    this.checkTemperature = function() {
        var packet = Buffer.alloc(16, 0);
        packet[0] = 1;
        this.sendPacket(0x6a, packet);
    }

    this.on("payload", (err, payload) => {
        var param = payload[0];
        switch (param) {
            case 1:
                var temp = (payload[0x4] * 10 + payload[0x5]) / 10.0;
                this.emit("temperature", temp);
                break;
            case 4: //get from check_data
                var data = Buffer.alloc(payload.length - 4, 0);
                payload.copy(data, 0, 4);
                this.emit("rawData", data);
                break;
            case 3:
                break;
            case 4:
                break;
        }
    });
}