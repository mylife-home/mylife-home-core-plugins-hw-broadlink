'use strict';

const Device   = require('./device');

class MP1 extends Device {
  constructor(host, type) {
    super(host, 0x4EB5);
  }

  checkState(done) {
    this._state(false, null, null, done);
  }

  setState(outputId, value, done) {
    this._state(true, outputId, value, done);
  }

  _state(change, outputId, value, done) {

    const payload = Buffer.alloc(16);
    const mask    = change && 0x01 << (outputId - 1);

    payload[0x00] = change ? 0x0d : 0x0a;
    payload[0x02] = 0xa5;
    payload[0x03] = 0xa5;
    payload[0x04] = 0x5a;
    payload[0x05] = 0x5a;
    payload[0x06] = change ? (0xb2 + (value ? (mask << 1) : mask)): 0xae;
    payload[0x07] = 0xc0;
    payload[0x08] = change ? 0x02 : 0x01;
    if(change) {
      payload[0x0a] = 0x03;
      payload[0x0d] = mask;
      payload[0x0e] = value ? mask : 0;
    }

    this.query({
      command: 0x6a,
      payload
    }, (err, message) => {

      if(err) {
        done && done(err);
        return this.error(err);
      }

      const { payload } = message;
      const s1 = !!(payload[0x0e] & 0x01);
      const s2 = !!(payload[0x0e] & 0x02);
      const s3 = !!(payload[0x0e] & 0x04);
      const s4 = !!(payload[0x0e] & 0x08);
      const state = [ s1, s2, s3, s4 ];
      this.emit('state', state);
      done && done(null, state);
    });

  }
}

module.exports.MP1 = MP1;
