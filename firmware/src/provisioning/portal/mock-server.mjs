/*
 * Mock of the firmware's portal API, so the captive-portal UI can be driven in a real browser
 * without a Pico on the desk. It serves the real portal.html from this directory, so what gets
 * tested is what ships.
 *
 *   node mock-server.mjs            then open http://127.0.0.1:8799/
 *
 * The password "wrong" drives the badauth branch; everything else succeeds.
 *
 * SPDX-License-Identifier: MIT
 */
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

const PORTAL = process.argv[2] ?? new URL("./portal.html", import.meta.url);
const PORT = 8799;

const NETWORKS = [
  { ssid: 'HomeNet', rssi: -42, auth: 'wpa2', channel: 6 },
  { ssid: "Sarah's Wi-Fi 5GHz", rssi: -58, auth: 'wpa2', channel: 44 },
  { ssid: 'Café Münster 🏠', rssi: -66, auth: 'wpa2', channel: 1 },
  { ssid: 'BT-OpenZone', rssi: -71, auth: 'open', channel: 11 },
  { ssid: '', rssi: -79, auth: 'wpa2', channel: 3 },
  { ssid: 'A-really-long-network-name-that-should-ellipsize-not-wrap', rssi: -84, auth: 'wpa2', channel: 9 },
];

function json(res, obj, code = 200) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { return {}; }
}

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');

  if (url.pathname === '/api/info') {
    return json(res, {
      product: 'Remote Wake', device_id: 'a1b2c3d4e5f60718', fw: '1.0.0',
      board: 'pico2_w', configured: false, ssid: '',
    });
  }
  if (url.pathname === '/api/scan') {
    await new Promise((r) => setTimeout(r, 400)); // the real scan is slow; exercise the spinner
    return json(res, { networks: NETWORKS });
  }
  if (url.pathname === '/api/join') {
    const b = await readBody(req);
    await new Promise((r) => setTimeout(r, 300));
    // "wrong" is the magic password for driving the badauth branch.
    if (b.psk === 'wrong') return json(res, { ok: false, err: 'badauth' });
    return json(res, { ok: true, ip: '192.168.1.42' });
  }
  if (url.pathname === '/api/config') return json(res, { ok: true });
  if (url.pathname === '/api/commit') {
    return json(res, {
      ok: true, seq: 1, device_id: 'a1b2c3d4e5f60718',
      token: '9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0',
    });
  }

  // Everything else is the portal, which is also how the captive-portal probe redirects behave.
  const html = readFileSync(PORTAL);
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}).listen(PORT, () => console.log(`portal mock on http://127.0.0.1:${PORT}`));
