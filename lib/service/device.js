'use strict';

/*
inspired from :
 - https://github.com/smka/broadlinkjs-sm/blob/master/index.js
 - https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1
*/

const EventEmitter = require('events');
const crypto       = require('crypto');
const arp          = require('node-arp');
const dns          = require('dns');
const log4js       = require('log4js');
const logger       = log4js.getLogger('core-plugins-hw-broadlink.Device');
const Connection   = require('./connection');

const commands = {
  Auth        : [ 0x65, 0x3e9 ],
  TogglePower : [ 0x6a, 0x3ee ]
};

const defaultKey = Buffer.from([0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]);
const iv         = Buffer.from([0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58]);
const cid        = Buffer.from([0xa5,0xaa,0x55,0x5a,0xa5,0xaa,0x55,0x0]);

const checksum = (buffer) => ((0xbeaf + Array.prototype.slice.call(buffer, 0).reduce((p, c) => (p + c))) & 0xffff);

class Device extends EventEmitter {
  constructor(host) {
    super();

    this.host   = host;
    this.closed = false;
    this.reset();
  }

  reset() {
    this.address        = null;
    this.mac            = null;
    this.reconnectTimer = null;

    this.key         = defaultKey;
    this.deviceId    = null;
    this.sendCounter = 0;

    this.setOnline(false);
  }

  connect() {
    dns.resolve4(this.host, (err, addresses) => {
      if(err) { return this.error(err); }
      this.address = addresses[0];

      arp.getMAC(this.address, (err, mac) => {
        if(err) { return this.error(err); }

        this.mac = mac;

        logger.debug(`Connecting to (host='${this.host}', address=${this.address}, mac=${this.mac})`);

        this.socket = new Connection();
        this.socket.on('error', err => this.error(err));

        this.socket.open(this.address, err => {
          if(err) { return this.error(err); }
          this.auth();
        })
      });
    })
  }

  close() {
    this.closed = true;
    this.disconnect();
  }

  setOnline(value) {
    if(this.online === value) { return; }
    this.online = value;
    this.emit('online', this.online);
  }

  disconnect() {
    if(this.socket) {
      this.socket.close();
      this.socket = null;
    }

    if(this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reset();
  }

  error(err) {
    logger.error(err);

    this.disconnect();

    if(this.closed) {
      return;
    }

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 5000);
  }

  createPacket(message) {
    if(!message.payload) {
      message.payload = Buffer.alloc(0);
    }

    let packet = Buffer.alloc(0x38); // total custom header length
    packet.writeUInt8(0x5a, 0); // Version:0, Reset:Yes, CID:0x2,Packet #1, Multipath:Yes
    cid.copy(packet, 1);
    // tag:0x0, tag #:0x0, padding: 0
    packet.writeUInt16LE(0x7D00, 0x24); // 0x24  : Device ID ??
    packet.writeUInt8(message.command, 0x26); // 0x26  : Command
    packet.writeUInt16LE(this.sendCounter++ & 0xFFFF, 0x28); //      0x28  : Send Counter

    const m = this.mac.split(':').reverse();
    let offset = 0x2a; // 0x2a  : MAC
    for(var i=0; i<m.length; ++i) {
      packet.writeUInt8(parseInt(m[i], 16), offset++);
    }

    if(this.deviceId) {
      packet.writeUInt32LE(this.deviceId, 0x30); // 0x30  : Device ID
    }

    if(message.payload.length > 0) {
      packet.writeUInt16LE(checksum(message.payload), 52); // 0x34  : Header Checksum
    }

    const cipher = crypto.createCipheriv('aes-128-cbc', this.key, iv);
    cipher.setAutoPadding(false);
    message.payload = Buffer.concat([cipher.update(message.payload), cipher.final()]);

    packet = Buffer.concat([packet,message.payload]);
    packet.writeUInt16LE(checksum(packet), 0x20); // 0x20   : Full checksum
    return packet;
  }

  parsePacket(packet) {
    const id = packet.readUInt16LE(0x28);
    const cs = packet.readUInt16LE(0x20);
    packet.writeUInt16LE(0, 0x20);
    if(cs !== checksum(packet)) {
      throw new Error(`Bad checksum (#${id})`);
    }

    // TODO: should we ignore this for Auth ?
    const errCode = packet.readUInt16LE(0x22); // 0x22 : Error
    if(errCode !== 0) {
      throw new Error(`Error status in response: ${errCode} (#${id})`);
    }

    let payload = Buffer.alloc(packet.length - 0x38); // 0x38 : Encrypted payload
    packet.copy(payload, 0, 56, packet.length);

    var decipher = crypto.createDecipheriv('aes-128-cbc', this.key, iv);
    decipher.setAutoPadding(false);
    payload = Buffer.concat([decipher.update(payload) , decipher.final()]);

    return { payload };
  }

  query(message, done) {
    const request = this.createPacket(message);
    this.socket.query(request, (err, response) => {
      if(err) { return done(err); }
      let rmessage;
      try {
        rmessage = this.parsePacket(reponse);
      } catch(err) {
        return done(err);
      }
      return done(null, rmessage);
    });
  }

  auth() {
    const payload = Buffer.alloc(0x50);
    const key = crypto.randomBytes(16); // this.key;
    key.copy(payload, 0x4); //  0x4 : Shared key (16 bytes)
    //payload.writeUInt8(0x1, 0x1e); // 0x1e : 0x1
    payload.writeUInt8(0x1, 0x2d); // 0x2d : 0x1
    payload.write('mylife-home', 0x30, 'ascii'); // 0x30 : Device name

    this.query({
      command: commands.Auth[0],
      payload
    }, (err, message) => {
      if(err) { return this.error(err); }
      const { payload } = message;
      const key = Buffer.alloc(16);
      payload.copy(key, 0, 0x4, 20); // 0x4 : key in payload
      this.key = key;
      this.deviceId = payload.readInt32LE(0x0); // 0x0 : device id in payload

      logger.debug(`Authenticated (deviceId=${this.deviceId}, key=${this.key.toString('hex')})`);

      this.setOnline(true);
    });
  }

}

module.exports = Device;
