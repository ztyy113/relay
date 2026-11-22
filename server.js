// 零依赖 VLESS-over-WebSocket 服务端（Node 18+，可直接跑在 Render 免费实例）
// 环境变量：UUID（必须）、PORT（Render 自动注入）
const http = require("http");
const crypto = require("crypto");
const net = require("net");

const UUID = (process.env.UUID || "23f25384-e61b-40d7-b865-8c5d933b4d26").toLowerCase();
const PORT = process.env.PORT || 10000;

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

function acceptKey(key) {
  return crypto.createHash("sha1").update(key + GUID).digest("base64");
}

function frame(payload) {
  const len = payload.length;
  let head;
  if (len < 126) {
    head = Buffer.from([0x82, len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x82; head[1] = 126; head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x82; head[1] = 127;
    head.writeUInt32BE(Math.floor(len / 4294967296), 2);
    head.writeUInt32BE(len >>> 0, 6);
  }
  return Buffer.concat([head, payload]);
}

// 解析 buffer 里完整帧，返回 [frames, 已消费字节数]
function parseFrames(buf) {
  const frames = [];
  let off = 0;
  while (buf.length - off >= 2) {
    const b1 = buf[off + 1];
    const opcode = buf[off] & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let p = off + 2;
    if (len === 126) {
      if (buf.length < p + 2) break;
      len = buf.readUInt16BE(p); p += 2;
    } else if (len === 127) {
      if (buf.length < p + 8) break;
      len = Number(buf.readBigUInt64BE(p)); p += 8;
    }
    const need = masked ? len + 4 : len;
    if (buf.length < p + need) break;
    let data;
    if (masked) {
      const mask = buf.slice(p, p + 4); p += 4;
      data = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) data[i] = buf[p + i] ^ mask[i & 3];
    } else {
      data = buf.slice(p, p + len);
    }
    off = p + len;
    frames.push({ opcode, data });
  }
  return [frames, off];
}

const server = http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
  res.end("vless-relay ok " + new Date().toISOString());
});

server.on("upgrade", (req, socket) => {
  const path = new URL(req.url, "http://x").pathname.replace(/^\//, "").toLowerCase();
  if (path !== UUID) { socket.destroy(); return; }

  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " + acceptKey(req.headers["sec-websocket-key"]) + "\r\n\r\n"
  );
  socket.setNoDelay(true);

  let raw = Buffer.alloc(0);
  let pending = Buffer.alloc(0);
  let tcp = null;
  let ready = false;

  const send = (buf) => { try { socket.write(frame(buf)); } catch (e) {} };
  const cleanup = () => {
    ready = false;
    try { tcp && tcp.destroy(); } catch (e) {}
    try { socket.destroy(); } catch (e) {}
  };

  function tryStart() {
    if (ready || pending.length < 24) return;
    const ver = pending[0];
    const id = pending.slice(1, 17).toString("hex")
      .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5").toLowerCase();
    if (id !== UUID) { cleanup(); return; }
    const addon = pending[17];
    let p = 18 + addon;
    if (pending.length < p + 4) return;
    const cmd = pending[p];
    const port = pending.readUInt16BE(p + 1);
    const atyp = pending[p + 3];
    p += 4;
    let host = "";
    if (atyp === 1) {
      if (pending.length < p + 4) return;
      host = `${pending[p]}.${pending[p + 1]}.${pending[p + 2]}.${pending[p + 3]}`; p += 4;
    } else if (atyp === 2) {
      if (pending.length < p + 1) return;
      const n = pending[p];
      if (pending.length < p + 1 + n) return;
      host = pending.slice(p + 1, p + 1 + n).toString(); p += 1 + n;
    } else if (atyp === 3) {
      if (pending.length < p + 16) return;
      const seg = [];
      for (let i = 0; i < 8; i++) seg.push(pending.readUInt16BE(p + i * 2).toString(16));
      host = seg.join(":"); p += 16;
    } else { cleanup(); return; }
    if (cmd !== 1) { cleanup(); return; }

    const rest = pending.slice(p);
    pending = Buffer.alloc(0);
    ready = true;

    tcp = net.connect({ host, port }, () => {
      send(Buffer.from([ver, 0]));
      if (rest.length) tcp.write(rest);
    });
    tcp.on("data", send);
    tcp.on("close", cleanup);
    tcp.on("error", cleanup);
  }

  socket.on("data", (chunk) => {
    raw = Buffer.concat([raw, chunk]);
    const [frames, used] = parseFrames(raw);
    raw = raw.slice(used);
    for (const f of frames) {
      if (f.opcode === 0x8) { cleanup(); return; }
      if (f.opcode === 0x1 || f.opcode === 0x2 || f.opcode === 0x0) {
        if (ready) { if (tcp && !tcp.destroyed) tcp.write(f.data); }
        else { pending = Buffer.concat([pending, f.data]); tryStart(); }
      }
    }
  });

  socket.on("error", cleanup);
  socket.on("close", cleanup);
});

server.listen(PORT, () => console.log("vless relay listening on " + PORT));
