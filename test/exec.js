'use strict';

const Device = require('../lib/service/device');

// smart-plug1

const device = new Device('smart-plug1.mti-team2.dyndns.org');

device.connect();