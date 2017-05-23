'use strict';

const async   = require('async');
const { MP1 } = require('../lib/service/devices');
const log4js  = require('log4js');
const logger  = log4js.getLogger('core-plugins-hw-broadlink.MP1');

module.exports = class {
  constructor(config) {
    this._host = config.host;

    this.online = 'off';

    this.o1 = 'off';
    this.o2 = 'off';
    this.o3 = 'off';
    this.o4 = 'off';

    this._device = new MP1(this._host);
    this._onlineCallback = (value) => this._onOnline(value);
    this._device.on('online', this._onlineCallback);
    this._device.connect();

    this._enforcer = setInterval(() => this._enforceState(), 10000);
    this._busy = false;
  }

  close(done) {
    this._device.removeListener('online', this._onlineCallback);
    this._device.close();

    clearInterval(this._enforcer);

    setImmediate(done);
  }

  _onOnline(value) {
    this.online = value ? 'on' : 'off';
    this._enforceState();
  }

  _enforceState() {
    if(!this._device.online) { return; }
    if(this._busy) { return; }

    this._busy = true;
    this._device.checkState((err, state) => {

      if(err) {
        this._busy = false;
        return;
      }

      const createSetter = (i, propState) => cb => {
        logger.debug(`Updating state for output ${i} to ${propState}`);
        this._device.setState(i, propState, cb);
      };

      const jobs = [];
      for(let i=0; i<4; ++i) {
        const propState = this[`o${i + 1}`] === 'on';
        if(state[i] === propState) { continue; }

        jobs.push(createSetter(i + 1, propState));
      }

      if(!jobs.length) {
        this._busy = false;
        return;
      }

      async.series(jobs, () => { this._busy = false; });
    })
  }

  set1(value) {
    this.o1 = value;
    this._enforceState();
  }

  set2(value) {
    this.o2 = value;
    this._enforceState();
  }

  set3(value) {
    this.o3 = value;
    this._enforceState();
  }

  set4(value) {
    this.o4 = value;
    this._enforceState();
  }

  static metadata(builder) {
    const binary = builder.enum('off', 'on');

    builder.usage.driver();

    builder.attribute('online', binary);
    builder.attribute('o1', binary);
    builder.attribute('o2', binary);
    builder.attribute('o3', binary);
    builder.attribute('o4', binary);

    builder.action('set1', binary);
    builder.action('set2', binary);
    builder.action('set3', binary);
    builder.action('set4', binary);

    builder.config('host', 'string');
  }
};
