#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
spacedesk_client.py -- Premier client Linux pour spacedesk (reverse-engineere).

Se connecte au driver spacedesk (le "serveur" Windows) en TCP brut sur 28252,
recoit le flux video sous forme de TUILES JPEG (regions modifiees de l'ecran),
les recompose sur un <canvas> cote client via WebSocket, et renvoie les
evenements tactiles/souris vers le driver.

Stdlib uniquement (Python 3). Aucune dependance pip.

Protocole driver (little-endian) :
  - Handshake 462 o (header 128 + payload 334) envoye a la connexion.
  - Reception en boucle : header 128 o, plen=u32@4, payload=[128:128+plen].
    type=u32@0 : 1=Ping 2=FrameBuffer(tuile JPEG) 3=Visibility 4=CursorPos
                 5=CursorBitmap 9=Rotation.
  - FrameBuffer (type 2), header 128 o :
      off8  = largeur ecran total, off12 = hauteur ecran total
      off24 = left, off28 = top, off32 = right, off36 = bottom (Rect tuile)
      payload = JPEG de la tuile (dimensions = right-left x bottom-top)
  - Input : paquets 128 o. 12=Touch, 10=Mouse, 11=Keyboard.

Rendu client = WebSocket /ws :
  Pour chaque tuile, le daemon pousse une frame WS binaire :
      [left u32][top u32][w u32][h u32] (LE, 16 o) + octets JPEG.
  A la connexion, le daemon pousse d'abord une frame TEXTE JSON {"w":..,"h":..}
  (resolution ecran) pour dimensionner le canvas.

Connexion a la demande : la TCP vers le driver n'est ouverte que tant qu'au
moins un client (WS ou MJPEG) est connecte.
"""

import os
import socket
import struct
import threading
import time
import uuid
import json
import hashlib
import base64
import collections
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# --- Configuration (surchargeable par variables d'environnement) ---------
# IP du PC Windows qui fait tourner le driver spacedesk. OBLIGATOIRE a definir.
DRIVER_HOST = os.environ.get("SPACEDESK_DRIVER", "192.168.1.10")
DRIVER_PORT = int(os.environ.get("SPACEDESK_PORT", "28252"))
HTTP_HOST = os.environ.get("SPACEDESK_HTTP_HOST", "127.0.0.1")
HTTP_PORT = int(os.environ.get("SPACEDESK_HTTP_PORT", "8091"))
REQ_WIDTH = int(os.environ.get("SPACEDESK_WIDTH", "1280"))    # resolution ecran etendu (16:9)
REQ_HEIGHT = int(os.environ.get("SPACEDESK_HEIGHT", "720"))
JPEG_QUALITY = int(os.environ.get("SPACEDESK_QUALITY", "50"))  # 1-100, plus bas = plus fluide
MAX_FPS = int(os.environ.get("SPACEDESK_FPS", "30"))           # plafond via throttle FlowControlAck
DEVICE_NAME = os.environ.get("SPACEDESK_NAME", "linux-client")

HEADER_LEN = 128
HANDSHAKE_PAYLOAD_LEN = 334
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Flag anti-veille lu par presence.py : tant qu'un client viewer est connecte,
# on empeche la mise en veille / le gel de chromium (pkill -STOP). Flag DEDIE
# (suffixe _screen) pour ne pas entrer en conflit avec celui du dashboard.
KEEPAWAKE_FLAG = "/tmp/venue_keepawake_screen"


def log(msg):
    try:
        sys.stderr.write("[spacedesk] %s\n" % msg)
        sys.stderr.flush()
    except Exception:
        pass


def _set_keepawake(on):
    import os
    try:
        if on:
            open(KEEPAWAKE_FLAG, "w").close()
        elif os.path.exists(KEEPAWAKE_FLAG):
            os.remove(KEEPAWAKE_FLAG)
    except Exception:
        pass

# Types paquets
T_PING = 1
T_FRAMEBUFFER = 2
T_FLOWCONTROL_ACK = 7
T_DISCONNECT = 8
T_MOUSE = 10
T_KEYBOARD = 11
T_TOUCH = 12

# Le driver decoupe chaque frame en FRAGMENTS_PER_FRAME bandes et n'envoie la
# frame suivante qu'apres avoir recu un FlowControlAck (type 7). Le client
# officiel n'ACK qu'une fois les 4 fragments recus (fragmentCounter % 4 == 0),
# ou immediatement pour une tuile non fragmentee (fragmentInfo != 1).
FRAGMENTS_PER_FRAME = 4


def build_flow_ack():
    p = bytearray(HEADER_LEN)
    struct.pack_into("<I", p, 0, T_FLOWCONTROL_ACK)
    struct.pack_into("<I", p, 4, 0)
    return bytes(p)


FLOW_ACK = build_flow_ack()

# ---------------------------------------------------------------------------
# Etat partage
# ---------------------------------------------------------------------------
_sock_lock = threading.Lock()
_frame_lock = threading.Lock()
_client_lock = threading.Lock()
_ws_lock = threading.Lock()

driver_sock = None
recv_generation = 0
last_jpeg = None                   # derniere tuile (fallback MJPEG)
client_count = 0                   # nb clients actifs (WS + MJPEG)
screen_w = REQ_WIDTH
screen_h = REQ_HEIGHT
ws_clients = []                    # liste de WSConn actifs


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------
def build_handshake():
    header = bytearray(HEADER_LEN)
    struct.pack_into("<I", header, 0, 0)
    struct.pack_into("<I", header, 4, HANDSHAKE_PAYLOAD_LEN)
    struct.pack_into("<I", header, 8, 4)
    struct.pack_into("<I", header, 12, 8)
    struct.pack_into("<I", header, 16, 0)                    # clientType = WindowsRemoteMonitor
    struct.pack_into("<I", header, 20, 3)
    struct.pack_into("<I", header, 24, 3)
    struct.pack_into("<I", header, 28, 2)
    struct.pack_into("<I", header, 32, JPEG_QUALITY)
    struct.pack_into("<I", header, 36, 65539)
    struct.pack_into("<H", header, 44, 60)
    struct.pack_into("<H", header, 46, 4)
    struct.pack_into("<I", header, 48, 1)
    struct.pack_into("<I", header, 52, REQ_WIDTH)
    struct.pack_into("<I", header, 56, 0)
    struct.pack_into("<I", header, 88, REQ_HEIGHT)
    struct.pack_into("<I", header, 92, 0)

    payload = bytearray(HANDSHAKE_PAYLOAD_LEN)
    struct.pack_into("<I", payload, 0, 1)
    off = 4
    guid = "{%s}" % str(uuid.uuid4())
    guid_b = guid.encode("utf-16-le")
    payload[off:off + len(guid_b)] = guid_b
    off += len(guid_b)
    payload[off:off + 2] = b"\x00\x00"
    off += 2
    name_b = DEVICE_NAME.encode("utf-16-le")
    payload[off:off + len(name_b)] = name_b
    return bytes(header) + bytes(payload)


# ---------------------------------------------------------------------------
# Reception : parse les tuiles et les diffuse aux clients WS
# ---------------------------------------------------------------------------
def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("driver closed connection")
        buf.extend(chunk)
    return bytes(buf)


def recv_loop(sock, generation):
    global last_jpeg, screen_w, screen_h
    frag_counter = 0        # compteur de fragments pour le flow-control (par connexion)
    last_ack = [0.0]
    min_ack = 1.0 / MAX_FPS if MAX_FPS else 0.0

    def do_ack():
        # throttle : borne le driver a MAX_FPS (evite qu'il noie un client lent).
        dt = min_ack - (time.time() - last_ack[0])
        if dt > 0:
            time.sleep(dt)
        send_packet(FLOW_ACK)
        last_ack[0] = time.time()

    try:
        while True:
            with _client_lock:
                if recv_generation != generation:
                    return
            header = _recv_exact(sock, HEADER_LEN)
            ptype = struct.unpack_from("<I", header, 0)[0]
            plen = struct.unpack_from("<I", header, 4)[0]
            payload = _recv_exact(sock, plen) if plen > 0 else b""

            if ptype == T_PING:
                # echo du Ping = keep-alive / flow-control : sans reponse le driver
                # peut throttler l'envoi des tuiles (image lente alors que CPU idle).
                try:
                    send_packet(header + payload)
                except Exception:
                    pass
                continue

            if ptype == T_DISCONNECT:
                log("driver a envoye Disconnect (type 8)")
                break

            if ptype == T_FRAMEBUFFER and payload:
                sw = struct.unpack_from("<I", header, 8)[0]
                sh = struct.unpack_from("<I", header, 12)[0]
                left = struct.unpack_from("<I", header, 24)[0]
                top = struct.unpack_from("<I", header, 28)[0]
                right = struct.unpack_from("<I", header, 32)[0]
                bottom = struct.unpack_from("<I", header, 36)[0]
                frag_info = struct.unpack_from("<I", header, 64)[0]
                w = right - left
                h = bottom - top
                if sw and sh:
                    if sw != screen_w or sh != screen_h:
                        screen_w, screen_h = sw, sh
                        _broadcast_resolution(sw, sh)
                with _frame_lock:
                    last_jpeg = payload
                # frame WS binaire : en-tete 16 o + JPEG
                tile_hdr = struct.pack("<IIII", left, top, w, h)
                _broadcast_tile(tile_hdr + payload)
                # FLOW CONTROL : sans ACK le driver attend son timeout (~1s) avant
                # la frame suivante. On reproduit la regle du client officiel :
                # ACK apres 4 fragments, ou immediatement si tuile non fragmentee.
                if frag_info == 1:
                    frag_counter += 1
                    if frag_counter % FRAGMENTS_PER_FRAME == 0:
                        frag_counter = 0
                        do_ack()
                else:
                    frag_counter = 0
                    do_ack()
    except Exception as e:
        log("recv_loop arret: %r" % e)
    finally:
        with _sock_lock:
            global driver_sock
            if driver_sock is sock:
                try:
                    sock.close()
                except Exception:
                    pass
                driver_sock = None


# ---------------------------------------------------------------------------
# Connexion / deconnexion driver a la demande
# ---------------------------------------------------------------------------
def _open_driver_connection():
    global driver_sock, recv_generation, last_jpeg
    with _sock_lock:
        if driver_sock is not None:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((DRIVER_HOST, DRIVER_PORT))
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        s.sendall(build_handshake())
        s.settimeout(None)
        driver_sock = s
        recv_generation += 1
        gen = recv_generation
        with _frame_lock:
            last_jpeg = None
        log("driver connecte %s:%d (%dx%d q%d %dfps)" % (
            DRIVER_HOST, DRIVER_PORT, REQ_WIDTH, REQ_HEIGHT, JPEG_QUALITY, MAX_FPS))
        threading.Thread(target=recv_loop, args=(s, gen), daemon=True).start()


def _close_driver_connection():
    global driver_sock, recv_generation, last_jpeg
    with _sock_lock:
        recv_generation += 1
        if driver_sock is not None:
            try:
                driver_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                driver_sock.close()
            except Exception:
                pass
            driver_sock = None
        with _frame_lock:
            last_jpeg = None


def driver_watchdog():
    """Reconnexion auto : tant qu'un viewer est ouvert, si le driver a ferme la
    connexion (glitch/timeout), on la rouvre en <1s -> l'ecran revient seul."""
    while True:
        time.sleep(1.0)
        try:
            with _client_lock:
                n = client_count
            with _sock_lock:
                alive = driver_sock is not None
            if n > 0 and not alive:
                _open_driver_connection()
                log("reconnexion driver auto (watchdog)")
        except Exception as e:
            log("watchdog echec: %r" % e)


def _ensure_connected():
    with _sock_lock:
        alive = driver_sock is not None
    if not alive:
        try:
            _open_driver_connection()
        except Exception:
            pass


def client_join():
    global client_count
    with _client_lock:
        client_count += 1
        first = client_count == 1
    if first:
        _set_keepawake(True)
        try:
            _open_driver_connection()
        except Exception:
            pass


def client_leave():
    global client_count
    with _client_lock:
        client_count -= 1
        if client_count < 0:
            client_count = 0
        last = client_count == 0
    if last:
        log("plus de client -> fermeture connexion driver")
        _set_keepawake(False)
        _close_driver_connection()


# ---------------------------------------------------------------------------
# Envoi input vers le driver
# ---------------------------------------------------------------------------
def send_packet(pkt):
    with _sock_lock:
        s = driver_sock
    if s is None:
        return
    try:
        s.sendall(pkt)
    except Exception:
        pass


def build_touch(x, y, phase):
    p = bytearray(HEADER_LEN)
    struct.pack_into("<I", p, 0, T_TOUCH)
    struct.pack_into("<i", p, 8, int(x))
    struct.pack_into("<i", p, 12, int(y))
    struct.pack_into("<I", p, 16, screen_w)
    struct.pack_into("<I", p, 20, screen_h)
    flags = 0x01
    if phase == "down":
        flags |= 0x02
    elif phase == "up":
        flags |= 0x04
    struct.pack_into("<I", p, 24, flags)
    struct.pack_into("<I", p, 28, int(time.time() * 1000) & 0xFFFFFFFF)
    return bytes(p)


def build_mouse(x, y, phase):
    p = bytearray(HEADER_LEN)
    struct.pack_into("<I", p, 0, T_MOUSE)
    struct.pack_into("<i", p, 8, int(x))
    struct.pack_into("<i", p, 12, int(y))
    struct.pack_into("<i", p, 16, 0)
    struct.pack_into("<I", p, 20, 0x01)
    return bytes(p)


# ---------------------------------------------------------------------------
# WebSocket (implementation stdlib : handshake + framing)
# ---------------------------------------------------------------------------
class WSConn:
    """Connexion WebSocket avec file d'envoi + thread dedie.

    L'envoi est DECOUPLE de la reception driver : recv_loop se contente
    d'empiler (enqueue, non bloquant) ; un thread par client vide la file. Si un
    client est lent (Chromium engorge en dynamique), sa file sature et on DROP
    ses plus vieilles tuiles au lieu de bloquer recv_loop -> le driver reste
    ACK-e en continu (plus de deconnexion) et la latence reste bornee.
    """
    MAXQ = 8

    def __init__(self, wfile):
        self.wfile = wfile
        self.alive = True
        self.q = collections.deque()
        self.cv = threading.Condition()
        self.sender = threading.Thread(target=self._run, daemon=True)
        self.sender.start()

    def _enqueue(self, opcode, data, drop_old=True):
        with self.cv:
            if not self.alive:
                return
            if drop_old and len(self.q) >= self.MAXQ:
                # drop la plus vieille tuile (region perimee, re-rafraichie apres)
                try:
                    self.q.popleft()
                except IndexError:
                    pass
            self.q.append((opcode, data))
            self.cv.notify()

    def send_binary(self, data):
        self._enqueue(0x2, data, drop_old=True)

    def send_text(self, text):
        # texte (resolution) = important : jamais droppe
        self._enqueue(0x1, text.encode("utf-8"), drop_old=False)

    def send_pong(self, data):
        self._enqueue(0xA, data, drop_old=False)

    def close(self):
        with self.cv:
            self.alive = False
            self.cv.notify()

    def _run(self):
        while True:
            with self.cv:
                while self.alive and not self.q:
                    self.cv.wait()
                if not self.alive:
                    return
                opcode, data = self.q.popleft()
            try:
                self._send_raw(opcode, data)
            except Exception:
                self.alive = False
                return

    def _send_raw(self, opcode, data):
        # frame serveur -> client, NON masquee
        b1 = 0x80 | opcode
        n = len(data)
        hdr = bytearray([b1])
        if n < 126:
            hdr.append(n)
        elif n < 65536:
            hdr.append(126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(127)
            hdr += struct.pack(">Q", n)
        self.wfile.write(bytes(hdr))
        self.wfile.write(data)
        self.wfile.flush()


def _ws_accept_key(key):
    h = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(h).decode("ascii")


def _broadcast_tile(data):
    with _ws_lock:
        clients = list(ws_clients)
    for c in clients:
        try:
            c.send_binary(data)
        except Exception:
            _drop_ws(c)


def _broadcast_resolution(w, h):
    msg = json.dumps({"w": w, "h": h})
    with _ws_lock:
        clients = list(ws_clients)
    for c in clients:
        try:
            c.send_text(msg)
        except Exception:
            _drop_ws(c)


def _drop_ws(c):
    with _ws_lock:
        if c in ws_clients:
            ws_clients.remove(c)


# ---------------------------------------------------------------------------
# Page viewer (canvas + WebSocket)
# ---------------------------------------------------------------------------
VIEWER_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>spacedesk viewer</title>
<style>
  html,body{margin:0;padding:0;height:100%;overflow:hidden;background:#000;}
  #wrap{position:fixed;inset:0;background:#000;overflow:hidden;}
  /* canvas en absolu plein cadre : aucun element ne peut le decaler */
  #c{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;
     touch-action:none;user-select:none;-webkit-user-select:none;display:block;
     image-rendering:auto;}
  html,body,#c,#wrap{cursor:none;}
  /* bouton overlay bien visible, hors flux -> ne decale RIEN */
  #fs{position:fixed;top:8px;left:8px;z-index:2147483647;width:42px;height:42px;
      border:2px solid rgba(255,255,255,0.92);border-radius:9px;
      background:rgba(0,0,0,0.62);color:#fff;font-size:22px;line-height:38px;
      text-align:center;cursor:pointer;padding:0;opacity:1;
      box-shadow:0 2px 8px rgba(0,0,0,.5);-webkit-tap-highlight-color:transparent;}
  #fs:active{background:rgba(0,0,0,0.85);}
</style>
</head>
<body>
<div id="wrap"><canvas id="c" width="1920" height="1080"></canvas></div>
<button id="fs" title="Plein ecran">&#9906;</button>
<script>
(function(){
  var canvas=document.getElementById('c');
  // desynchronized => canvas basse latence (court-circuite le compositing) ;
  // alpha:false => pas de canal alpha a composer = rendu plus rapide.
  var ctx=canvas.getContext('2d',{desynchronized:true,alpha:false})||canvas.getContext('2d');
  var RW=1920, RH=1080;

  // ---- Plein ecran ----
  function inFs(){ return document.fullscreenElement||document.webkitFullscreenElement; }
  function enterFs(){
    var el=document.documentElement;
    var fn=el.requestFullscreen||el.webkitRequestFullscreen;
    if(!fn){ console.warn('requestFullscreen indisponible'); return; }
    try{
      var r=fn.call(el);
      if(r&&r.catch) r.catch(function(err){ console.error('requestFullscreen rejete:',err); });
    }catch(e){ console.error('requestFullscreen exception:',e); }
  }
  function exitFs(){
    var fn=document.exitFullscreen||document.webkitExitFullscreen;
    if(fn){ try{ fn.call(document); }catch(e){ console.error(e); } }
  }
  var fsBtn=document.getElementById('fs');
  function updateFsBtn(){
    // toujours visible (opacite geree par le CSS) ; seule l'icone change
    if(inFs()){ fsBtn.innerHTML='&#10005;'; fsBtn.title='Revenir (quitter le plein ecran)'; }
    else{ fsBtn.innerHTML='&#9974;'; fsBtn.title='Plein ecran'; }
  }
  fsBtn.addEventListener('click',function(e){
    e.preventDefault(); e.stopPropagation();
    if(inFs()) exitFs(); else enterFs();
  });
  document.addEventListener('fullscreenchange',updateFsBtn);
  document.addEventListener('webkitfullscreenchange',updateFsBtn);
  updateFsBtn();
  // Passage auto au 1er pointerdown (geste utilisateur), sans bloquer l'input.
  function firstTap(){ if(!inFs()) enterFs(); window.removeEventListener('pointerdown',firstTap,true); }
  window.addEventListener('pointerdown',firstTap,true);

  // ---- Rendu tuiles ----
  function resize(w,h){
    if(w===RW && h===RH && canvas.width===w) return;
    RW=w; RH=h; canvas.width=w; canvas.height=h;
  }
  var decoding=0, MAXDEC=6;
  function drawTile(left,top,w,h,jpegBytes){
    var blob=new Blob([jpegBytes],{type:'image/jpeg'});
    if(self.createImageBitmap){
      if(decoding>=MAXDEC) return;   // trop en retard : drop (region re-rafraichie apres)
      decoding++;
      createImageBitmap(blob).then(function(bmp){
        ctx.drawImage(bmp,left,top); if(bmp.close) bmp.close(); decoding--;
      }).catch(function(){ decoding--; });
    } else {
      var img=new Image(); var url=URL.createObjectURL(blob);
      img.onload=function(){ ctx.drawImage(img,left,top); URL.revokeObjectURL(url); };
      img.src=url;
    }
  }

  // ---- WebSocket ----
  function connect(){
    var proto=location.protocol==='https:'?'wss':'ws';
    var ws=new WebSocket(proto+'://'+location.host+'/ws');
    ws.binaryType='arraybuffer';
    ws.onmessage=function(ev){
      if(typeof ev.data==='string'){
        try{ var m=JSON.parse(ev.data); if(m.w&&m.h) resize(m.w,m.h); }catch(e){}
        return;
      }
      var dv=new DataView(ev.data);
      if(ev.data.byteLength<16) return;
      var left=dv.getUint32(0,true), top=dv.getUint32(4,true);
      var w=dv.getUint32(8,true), h=dv.getUint32(12,true);
      var jpeg=new Uint8Array(ev.data,16);
      drawTile(left,top,w,h,jpeg);
    };
    ws.onclose=function(){ setTimeout(connect,1000); };
    ws.onerror=function(){ try{ws.close();}catch(e){} };
  }
  connect();

  // ---- Mapping coords : viser la resolution REELLE du canvas ----
  function mapCoords(clientX,clientY){
    // object-fit:contain => l'image est mise a l'echelle (min) et CENTREE dans le
    // canvas ; on calcule la vraie zone image pour que le tactile se superpose pile
    // a l'affichage, quel que soit le ratio du conteneur (iframe ou plein ecran).
    var r=canvas.getBoundingClientRect();
    var scale=Math.min(r.width/RW, r.height/RH);
    var dispW=RW*scale, dispH=RH*scale;
    var offX=r.left+(r.width-dispW)/2;
    var offY=r.top+(r.height-dispH)/2;
    var x=Math.round((clientX-offX)/scale);
    var y=Math.round((clientY-offY)/scale);
    x=Math.max(0,Math.min(RW-1,x));
    y=Math.max(0,Math.min(RH-1,y));
    return {x:x,y:y};
  }

  var lastSend=0, MIN_MS=33, pending=null, raf=false;
  function post(obj){ try{ fetch('/input',{method:'POST',body:JSON.stringify(obj),keepalive:true}); }catch(e){} }
  function sendMove(x,y){
    pending={t:'touch',s:'move',x:x,y:y};
    if(!raf){ raf=true; requestAnimationFrame(function(){
      raf=false; var now=Date.now();
      if(pending&&now-lastSend>=MIN_MS){ lastSend=now; post(pending); pending=null; }
      else if(pending){ sendMove(pending.x,pending.y); }
    }); }
  }

  canvas.addEventListener('touchstart',function(e){ e.preventDefault();
    var t=e.changedTouches[0]; var c=mapCoords(t.clientX,t.clientY);
    post({t:'touch',s:'down',x:c.x,y:c.y}); },{passive:false});
  canvas.addEventListener('touchmove',function(e){ e.preventDefault();
    var t=e.changedTouches[0]; var c=mapCoords(t.clientX,t.clientY);
    sendMove(c.x,c.y); },{passive:false});
  canvas.addEventListener('touchend',function(e){ e.preventDefault();
    var t=e.changedTouches[0]; var c=mapCoords(t.clientX,t.clientY);
    post({t:'touch',s:'up',x:c.x,y:c.y}); },{passive:false});

  var mdown=false;
  canvas.addEventListener('mousedown',function(e){ e.preventDefault(); mdown=true;
    var c=mapCoords(e.clientX,e.clientY); post({t:'touch',s:'down',x:c.x,y:c.y}); });
  canvas.addEventListener('mousemove',function(e){ if(!mdown)return;
    var c=mapCoords(e.clientX,e.clientY); sendMove(c.x,c.y); });
  window.addEventListener('mouseup',function(e){ if(!mdown)return; mdown=false;
    var c=mapCoords(e.clientX,e.clientY); post({t:'touch',s:'up',x:c.x,y:c.y}); });
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Serveur HTTP + WS
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/ws"):
            self._serve_ws()
        elif self.path == "/" or self.path.startswith("/index"):
            self._serve_html()
        elif self.path.startswith("/mjpeg"):
            self._serve_mjpeg()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.startswith("/input"):
            self._handle_input()
        else:
            self.send_error(404)

    def _serve_html(self):
        body = VIEWER_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _serve_ws(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self.send_error(400)
            return
        # NODELAY : evite le lag Nagle+delayed-ACK sur chaque tuile envoyee.
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        accept = _ws_accept_key(key)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        conn = WSConn(self.wfile)
        client_join()
        with _ws_lock:
            ws_clients.append(conn)
        # pousser la resolution connue immediatement
        try:
            conn.send_text(json.dumps({"w": screen_w, "h": screen_h}))
        except Exception:
            pass
        try:
            # boucle de lecture : on lit (et ignore) les frames client, gere le close/ping
            while conn.alive:
                if not self._ws_read_frame(conn):
                    break
        except Exception:
            pass
        finally:
            conn.close()
            _drop_ws(conn)
            client_leave()

    def _ws_read_frame(self, conn):
        rf = self.rfile
        hdr = rf.read(2)
        if len(hdr) < 2:
            return False
        b0, b1 = hdr[0], hdr[1]
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        length = b1 & 0x7F
        if length == 126:
            ext = rf.read(2)
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = rf.read(8)
            length = struct.unpack(">Q", ext)[0]
        mask = rf.read(4) if masked else b""
        data = rf.read(length) if length else b""
        if masked and data:
            data = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))
        if opcode == 0x8:      # close
            return False
        if opcode == 0x9:      # ping -> pong
            conn.send_pong(data)
        return True

    def _serve_mjpeg(self):
        # fallback : renvoie la derniere tuile brute (mosaique, non recommande)
        client_join()
        boundary = "frame"
        self.send_response(200)
        self.send_header("Cache-Control", "no-cache, private")
        self.send_header("Content-Type",
                         "multipart/x-mixed-replace; boundary=%s" % boundary)
        self.end_headers()
        try:
            while True:
                _ensure_connected()
                with _frame_lock:
                    frame = last_jpeg
                if frame:
                    hdr = ("--%s\r\nContent-Type: image/jpeg\r\n"
                           "Content-Length: %d\r\n\r\n" % (boundary, len(frame)))
                    self.wfile.write(hdr.encode("ascii"))
                    self.wfile.write(frame)
                    self.wfile.write(b"\r\n")
                time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            client_leave()

    def _handle_input(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            self.send_error(400)
            return
        t = data.get("t")
        if t == "touch":
            send_packet(build_touch(data.get("x", 0), data.get("y", 0), data.get("s", "move")))
        elif t == "mouse":
            send_packet(build_mouse(data.get("x", 0), data.get("y", 0), data.get("s", "move")))
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    _set_keepawake(False)   # nettoie un eventuel flag orphelin d'un crash precedent
    threading.Thread(target=driver_watchdog, daemon=True).start()
    server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), Handler)
    server.daemon_threads = True
    print("spacedesk client HTTP+WS on http://%s:%d" % (HTTP_HOST, HTTP_PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _close_driver_connection()


if __name__ == "__main__":
    main()
