// Device names (Clients -> Devices), shared by every page that shows a
// client: the address -> name map is fetched once a minute at most.
import { api } from './api.js';

export const deviceNames = $state({ map: {} });

let loadedAt = 0;
let pending = null;

/** Fetch the names, unless they are fresh (`force` fetches anyway). */
export function loadDeviceNames(force = false) {
  if (!force && pending && Date.now() - loadedAt < 60_000) return pending;
  loadedAt = Date.now();
  pending = api
    .devices(24 * 30)
    .then((data) => {
      const map = {};
      for (const d of data.devices || []) if (d.name) map[d.address] = d.name;
      deviceNames.map = map;
    })
    .catch(() => {});
  return pending;
}

/** The name of the device at `address`, or ''. */
export function deviceName(address) {
  return deviceNames.map[address] || '';
}

/** The address of the device named `text` (any case), else `text`. */
export function addressFor(text) {
  const wanted = String(text).trim().toLowerCase();
  if (!wanted) return text;
  for (const [address, name] of Object.entries(deviceNames.map)) {
    if (name.toLowerCase() === wanted) return address;
  }
  return text;
}
