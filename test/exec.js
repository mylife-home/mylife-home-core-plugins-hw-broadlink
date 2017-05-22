'use strict';

const async = require('async');
const { MP1 } = require('../lib/service/devices');

const device = new MP1('smart-plug1.mti-team2.dyndns.org');

device.connect();

device.on('state', console.log);

device.once('online', () => {
  async.series([
    cb => { console.log('checkState'); device.checkState(); cb(); },
    createPause(),
    createTask(1, true),
    createPause(),
    createTask(1, false),
    createTask(2, true),
    createTask(3, true),
    createTask(4, true),
    createPause(),
    createTask(2, false),
    createTask(3, false),
    createTask(4, false),
  ],
  (err) => err && console.error(err));
});

function createPause() {
  return cb => setTimeout(cb, 2000);
}

function createTask(id, value) {
  return cb => { console.log('setState', id, value); device.setState(id, value); cb(); };
}