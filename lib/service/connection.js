'use strict';

const EventEmitter = require('events');
const dgram        = require('dgram');
const log4js       = require('log4js');
const logger       = log4js.getLogger('core-plugins-hw-broadlink.Connection');

class Connection extends EventEmitter {

  open(address, done) {
    this.address = address;

    this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    this.socket.on('error', err => this.emit(err));
    this.socket.on('message', (msg, rinfo) => this.message(msg, rinfo));

    this.socket.bind({}, done);

    this.pendings = new Map();
  }

  close(done) {
    this.socket.close(done);
    for(const pending of this.pendings.values()) {
      clearTimeout(pending.timeout);
    }
    this.pendings = null;
  }

  query(packet, done) {
    this.socket.send(packet, 80, this.address);

    const id = packet.readUInt16LE(0x28);
    this.pendings.set(id, {
      id, cb: done, timeout: setTimeout(() => this.timeout(id), 3000)
    });
  }

  timeout(id) {
    const pending = this.pendings.get(id);
    this.pendings.delete(id);
    pending.cb(new Error(`Request timeout (#${id})`));
  }

  message(packet, rinfo) {
    const id = packet.readUInt16LE(0x28);
    const pending = this.pendings.get(id);
    if(!pending) {
      logger.error(`Unmatched response ignored (#${id})`);
      return;
    }

    clearTimeout(pending.timeout);
    this.pendings.delete(id);
    pending.cb(null, packet, rinfo);
  }
};

module.exports = Connection;