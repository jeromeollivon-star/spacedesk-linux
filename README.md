# spacedesk-linux

**The first Linux client for [spacedesk](https://spacedesk.net/).**

[spacedesk](https://spacedesk.net/) turns a tablet/phone into a second monitor for a
Windows PC. It ships official clients for Windows, Android, iOS and a (limited) HTML5
viewer — **but no native Linux client**. This project fills that gap: a small,
dependency-free Python daemon that speaks the spacedesk wire protocol directly, letting
**any Linux device become a touch-capable extended display** for a Windows PC running the
spacedesk driver.

It was built entirely by **reverse-engineering the spacedesk v2.x protocol** (the wire
format is documented below so others can build on it). It reaches **latency on par with the
official Android client** over Wi‑Fi.

> Tested against the spacedesk **Windows driver 2.2.31** with a Debian 13 tablet client.

---

## Features

- **Extended display**: shows a Windows PC's extended screen on any Linux device with a browser.
- **Touch / mouse input**: tap and drag on the Linux screen control the Windows cursor.
- **Fullscreen** with an on-screen toggle button.
- **Auto-reconnect** watchdog: if the driver drops the connection, it re-establishes in <1 s.
- **On-demand**: only connects to the driver while a viewer is open (no ghost display left behind).
- **Zero dependencies**: pure Python 3 standard library. No pip, no build step.
- **Low latency**: proper flow-control acknowledgement, `TCP_NODELAY`, tile compositing on a
  `<canvas>`, decoupled send/receive with frame-dropping under load.

## How it works

```
Windows PC (spacedesk driver, TCP :28252)
        ▲  JPEG tiles          │ FlowControlAck / input
        │                      ▼
   spacedesk_client.py  (this daemon, on the Linux device)
        │  WebSocket (binary tiles) / HTTP
        ▼
   Browser viewer  →  <canvas>  +  touch/mouse capture
```

The daemon connects to the driver over **raw TCP** (not WebSocket), performs the
identification handshake as a `WindowsRemoteMonitor` client, receives the screen as **JPEG
tiles**, and re-broadcasts them to a local browser viewer over WebSocket where they are
composited onto a `<canvas>`. Touch/mouse events are captured in the browser and sent back
to the driver as input packets.

## Requirements

- A Windows PC running the **spacedesk driver** (Server), reachable over the network.
- A Linux device with **Python 3** and a modern browser (Chromium/Firefox).

## Usage

```bash
# Point it at your spacedesk Windows PC and run it:
SPACEDESK_DRIVER=192.168.1.42 python3 spacedesk_client.py
```

Then open **http://127.0.0.1:8091/** in a browser on the Linux device. An extended display
appears on Windows and mirrors onto the browser; tap to control it. Tap the ⛶ button (top-left)
for fullscreen.

### Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `SPACEDESK_DRIVER` | `192.168.1.10` | IP of the Windows PC running the driver **(set this!)** |
| `SPACEDESK_PORT` | `28252` | Driver TCP port |
| `SPACEDESK_HTTP_HOST` | `127.0.0.1` | Bind address of the local viewer server |
| `SPACEDESK_HTTP_PORT` | `8091` | Port of the local viewer server |
| `SPACEDESK_WIDTH` / `SPACEDESK_HEIGHT` | `1280` / `720` | Requested extended-display resolution |
| `SPACEDESK_QUALITY` | `50` | JPEG quality requested (1–100) |
| `SPACEDESK_FPS` | `30` | Frame cap (throttles flow-control ACKs) |
| `SPACEDESK_NAME` | `linux-client` | Device name shown on the driver |

### Run as a service

See [`spacedesk-client.service`](spacedesk-client.service) for a ready-made systemd unit.

```bash
sudo cp spacedesk_client.py /opt/spacedesk/
sudo cp spacedesk-client.service /etc/systemd/system/
sudo systemctl enable --now spacedesk-client
```

## Protocol notes (reverse-engineered, spacedesk v2.x)

All integers **little-endian**. Every packet = 128-byte header + optional payload
(`payloadLen = u32 @ offset 4`). Header types (`u32 @ 0`):
`1=Ping 2=FrameBuffer 3=Visibility 4=CursorPos 5=CursorBmp 7=FlowControlAck 8=Disconnect
9=Rotation 10=Mouse 11=Keyboard 12=Touch`.

**Handshake** (462 bytes = header 128 + payload 334), sent on connect:
`off0=0` (Identification), `off4=334`, `off8=4`/`off12=8` (version 4.8),
**`off16=0` = clientType `WindowsRemoteMonitor` (critical)**, `off20=3`, `off24=3` (compression),
`off28=2`, `off32=quality`, `off36=0x10003`, `off44(u16)=fps`, `off46(u16)=4`, `off48=1`,
`off52=width`, `off88=height`. Payload: `u32=1` + GUID `{…}` UTF‑16LE + `00 00` + device name UTF‑16LE.

**FrameBuffer (2)** — payload is a **JPEG tile**. Header: `off8/12`=full screen size,
`off24/28/32/36`=tile rect (left/top/right/bottom), `off64`=fragmentInfo (`==1` if fragment).
The driver splits each frame into **4 horizontal bands**; composite them at their rect on a canvas.

**FlowControlAck (7)** — header only (`off0=7`, `off4=0`). **This is the latency key.** The
driver won't send the next frame until it receives this ACK. The official client ACKs once per
frame: after 4 fragments (`fragmentCounter % 4 == 0`), or immediately for a non-fragmented tile.
Without it you get ~1 s of latency per frame.

**Input** (128-byte header, no payload):
- **Touch (12)**: `off8`=X `off12`=Y `off16`=resX `off20`=resY `off24`=flags (`0x01` absolute
  | `0x02` down | `0x04` up) `off28`=timestamp.
- **Mouse (10)**: `off8`=X `off12`=Y `off16`=wheelDelta `off20`=buttonData `off24`=flags (`0x01`=move).

## Limitations

- Latency is that of spacedesk itself over Wi‑Fi (a wired/USB-Ethernet link helps a lot).
- Touch is *absolute* — pointing at small Windows targets on a small screen can be fiddly
  (a relative "trackpad" mode is a planned improvement).
- Reverse-engineered and unofficial; not affiliated with or endorsed by spacedesk / Datronicsoft.

## License

MIT — see [LICENSE](LICENSE).
