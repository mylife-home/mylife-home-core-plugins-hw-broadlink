'use strict';

const async   = require('async');
const { SP3 } = require('../lib/service/devices');
const log4js  = require('log4js');
const logger  = log4js.getLogger('core-plugins-hw-broadlink.SP3');

module.exports = class {
  constructor(config) {
    this._host = config.host;

    this.online = 'off';

    this.value = 'off';

    this._device = new SP3(this._host);
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

      const newValue = this.value === 'on';
      if(state === newValue) {
        this._busy = false;
        return;
      }

      logger.debug(`Updating state to ${newValue}`);
      this._device.setState(newValue, () => { this._busy = false; });
    })
  }

  setValue(value) {
    this.value = value;
    this._enforceState();
  }

  static metadata(builder) {
    const binary = builder.enum('off', 'on');

    builder.usage.driver();

    builder.attribute('online', binary);
    builder.attribute('value', binary);

    builder.action('setValue', binary);

    builder.config('host', 'string');
  }
};
