# Container-Scan: app-node

- Image: node:22.22.0-alpine (sha256:e4bf2a82ad0a)  
- OS: Alpine Linux v3.23  
- Zeitpunkt: 2026-11-07 20:37  
- Scanner: container-security-scan 0.1.0  
- Datenbank: OSV, Stand 2026-11-07 14:13 UTC (daten)  
- Erfassung: OS-Pakete apk; Dateien find/tar im Container (inkl. 1 Volumes); Prozesse im Container (je Prozess-Benutzer)

## Ergebnis

**Warnung:** Öffentlicher Dienst node:3000 läuft als root (UID 0, ohne unprivilegierte Worker) – eine Lücke darin gibt root im Container; Benutzer setzen (user:, USER) oder non-root-Image  
**13 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

Davon **0 neu** seit dem letzten Lauf.

- **CVE-2026-111497** (CRITICAL KEV) in node 22.22.0 – behoben in 22.23.4 – genutzt von node:3000 – **aktiv ausgenutzt** (KEV seit 2026-10-27)
- **CVE-2021-23337** (HIGH) in lodash 4.17.20 – behoben in 4.17.21 – genutzt von node:3000
- **CVE-2026-4800** (HIGH) in lodash 4.17.20 – behoben in 4.18.0 – genutzt von node:3000
- **CVE-2026-107891** (HIGH) in musl 1.2.5-r21 – behoben in 1.2.5-r24 – genutzt von node:3000
- **CVE-2026-40200** (HIGH) in musl 1.2.5-r21 – behoben in 1.2.5-r23 – genutzt von node:3000
- **CVE-2026-105482** (HIGH) in node 22.22.0 – behoben in 22.23.4 – genutzt von node:3000
- **CVE-2026-106069** (HIGH) in node 22.22.0 – behoben in 22.23.4 – genutzt von node:3000
- **CVE-2026-21710** (HIGH) in node 22.22.0 – behoben in 22.22.2 – genutzt von node:3000
- **CVE-2026-48617** (HIGH) in node 22.22.0 – behoben in 22.23.0 – genutzt von node:3000
- **CVE-2026-48937** (HIGH) in node 22.22.0 – behoben in 22.23.0 – genutzt von node:3000
- **CVE-2026-56846** (HIGH) in node 22.22.0 – behoben in 22.23.2 – genutzt von node:3000
- **CVE-2026-56848** (HIGH) in node 22.22.0 – behoben in 22.23.2 – genutzt von node:3000
- **CVE-2026-58043** (HIGH) in node 22.22.0 – behoben in 22.23.2 – genutzt von node:3000

Gefährliche Einstellungen des Containers (privileged, Docker-Socket, pid=host …): keine gezählt.

## Laufende Dienste

| Dienst | Programm | Ports / Konfiguration |
|---|---|---|
| node:3000 | node 22.22.0 | Port 3000/tcp (alle) öffentlich über nginx:80 in app-proxy, traefik:80 in app-traefik; Anwendung: server.js; Arbeitsverzeichnis: /app |

## Übersicht (Anzahl Befunde)

| Priorität | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
|---|---|---|---|---|---|
| P1 Dienst mit veröffentlichtem Port | 1 | 12 | 14 | 8 | 0 |
| P2 Dienst intern | 0 | 0 | 0 | 0 | 0 |
| P3 Prozess ohne Port | 0 | 0 | 0 | 0 | 0 |
| P4 nicht genutzt / dev | 12 | 82 | 34 | 7 | 0 |

## Befunde (129 von 170; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Titel |
|---|---|---|---|---|---|---|---|
| 1 | CRITICAL KEV | CVE-2026-111497 | node | 22.22.0 | 22.23.4 | node:3000 | A flaw in Node.js can cause Node.js Brotli decoder out-of-bounds write permits remote code |
| 1 | HIGH | CVE-2021-23337 | lodash | 4.17.20 | 4.17.21 | node:3000 | Command Injection in lodash |
| 1 | HIGH | CVE-2026-4800 | lodash | 4.17.20 | 4.18.0 | node:3000 | lodash vulnerable to Code Injection via `_.template` imports key names |
| 1 | HIGH | CVE-2026-107891 | musl | 1.2.5-r21 | 1.2.5-r24 | node:3000 | musl libc before 1.2.7, when an untrusted regular expression is used with regcomp, has mul |
| 1 | HIGH | CVE-2026-40200 | musl | 1.2.5-r21 | 1.2.5-r23 | node:3000 | An issue was discovered in musl libc 0.7.10 through 1.2.6. Stack-based memory corruption c |
| 1 | HIGH | CVE-2026-105482 | node | 22.22.0 | 22.23.4 | node:3000 | A flaw in Node.js DNS resolution allows hostnames containing a NUL byte to be silently tru |
| 1 | HIGH | CVE-2026-106069 | node | 22.22.0 | 22.23.4 | node:3000 | A flaw in Node.js TLS hostname verification can cause a server certificate to be validated |
| 1 | HIGH | CVE-2026-21710 | node | 22.22.0 | 22.22.2 | node:3000 | A flaw in Node.js HTTP request handling causes an uncaught `TypeError` when a request is r |
| 1 | HIGH | CVE-2026-48617 | node | 22.22.0 | 22.23.0 | node:3000 | A flaw in Node.js Permission Model enforcement allows Bypass via `process.report.writeRepo |
| 1 | HIGH | CVE-2026-48937 | node | 22.22.0 | 22.23.0 | node:3000 | A flaw in Node.js HTTP/2 server API can cause servers to keep accepting data even after se |
| 1 | HIGH | CVE-2026-56846 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js HTTP/2 handling can cause HTTP/2 retained header blocks evade maxSession |
| 1 | HIGH | CVE-2026-56848 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js HTTP/2 handling allows `nghttp2_session_mem_send()` to be called re-entr |
| 1 | HIGH | CVE-2026-58043 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js Permission Model enforcement can over-grant filesystem access across rad |
| 1 | MEDIUM | CVE-2020-28500 | lodash | 4.17.20 | 4.17.21 | node:3000 | Regular Expression Denial of Service (ReDoS) in lodash |
| 1 | MEDIUM | CVE-2025-13465 | lodash | 4.17.20 | 4.17.23 | node:3000 | Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functi |
| 1 | MEDIUM | CVE-2026-105481 | node | 22.22.0 | 22.23.4 | node:3000 | A flaw in Node.js HTTP Agent connection reuse can cause a client to accept as valid a resp |
| 1 | MEDIUM | CVE-2026-106072 | node | 22.22.0 | 22.23.4 | node:3000 | A flaw in Node.js TLS hostname verification allows a certificate with only a DNS SAN to au |
| 1 | MEDIUM | CVE-2026-106074 | node | 22.22.0 | 22.23.4 | node:3000 | A flaw in Node.js `crypto` causes the internal entropy caches used by `crypto.randomUUID() |
| 1 | MEDIUM | CVE-2026-21713 | node | 22.22.0 | 22.22.2 | node:3000 | A flaw in Node.js HMAC verification uses a non-constant-time comparison when validating us |
| 1 | MEDIUM | CVE-2026-21714 | node | 22.22.0 | 22.22.2 | node:3000 | A memory leak occurs in Node.js HTTP/2 servers when a client sends WINDOW_UPDATE frames on |
| 1 | MEDIUM | CVE-2026-21717 | node | 22.22.0 | 22.22.2 | node:3000 | A flaw in V8's string hashing mechanism causes integer-like strings to be hashed to their  |
| 1 | MEDIUM | CVE-2026-56847 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js Permission Model enforcement allows `trace_events.createTracing().enable |
| 1 | MEDIUM | CVE-2026-56850 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js HTTPS Agent connection reuse can cause PFX object-array key collisions,  |
| 1 | MEDIUM | CVE-2026-58040 | node | 22.22.0 | 22.23.2 | node:3000 | An incomplete fix has been identified in Node.js: HTTPS Agent TLS session reuse skips host |
| 1 | MEDIUM | CVE-2026-58041 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js node:sqlite allows a stale StatementSyncIterator created through Databas |
| 1 | MEDIUM | CVE-2026-58042 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js can cause dns.resolveAny() Aborts the Node.js Process When a DNS Respons |
| 1 | MEDIUM | CVE-2026-58045 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js allows a spoofed `TypedArray` `byteLength` to trigger a reachable assert |
| 1 | LOW | CVE-2026-6042 | musl | 1.2.5-r21 | 1.2.5-r22 | node:3000 | A security flaw has been discovered in musl libc up to 1.2.6. Affected is the function ico |
| 1 | LOW | CVE-2026-106073 | node | 22.22.0 | 22.23.4 | node:3000 | A flaw in Node.js Permission Model filesystem enforcement leaves `fs.realpathSync()` witho |
| 1 | LOW | CVE-2026-21715 | node | 22.22.0 | 22.22.2 | node:3000 | A flaw in Node.js Permission Model filesystem enforcement leaves `fs.realpathSync.native() |
| 1 | LOW | CVE-2026-21716 | node | 22.22.0 | 22.22.2 | node:3000 | An incomplete fix for CVE-2024-36137 leaves `FileHandle.chmod()` and `FileHandle.chown()`  |
| 1 | LOW | CVE-2026-48931 | node | 22.22.0 | 22.23.0 | node:3000 | A flaw in Node.js HTTP Agent can cause a client to accept as valid a response that is send |
| 1 | LOW | CVE-2026-48932 | node | 22.22.0 | 22.23.0 | node:3000 | A flaw in Node.js HTTP client can cause a request desynchronization for Node.js-based forw |
| 1 | LOW | CVE-2026-58039 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js Permission Model enforcement allows process.report writes (and overwrite |
| 1 | LOW | CVE-2026-58044 | node | 22.22.0 | 22.23.2 | node:3000 | A flaw in Node.js HTTP client can cause a request desynchronization for Node.js-based forw |
| 4 | CRITICAL | CVE-2026-31789 | libcrypto3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: Converting an excessively large OCTET STRING value to |
| 4 | CRITICAL | CVE-2026-34182 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue Summary: Cryptographic Message Services (CMS) processing fails to perform |
| 4 | CRITICAL | CVE-2026-63073 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: OpenSSL CMP response validation passed an unexpected response |
| 4 | CRITICAL | CVE-2026-75803 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: ChaCha20-Poly1305 and AES-OCB decryption with an empty |
| 4 | CRITICAL | CVE-2026-31789 | libssl3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: Converting an excessively large OCTET STRING value to |
| 4 | CRITICAL | CVE-2026-34182 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue Summary: Cryptographic Message Services (CMS) processing fails to perform |
| 4 | CRITICAL | CVE-2026-63073 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: OpenSSL CMP response validation passed an unexpected response |
| 4 | CRITICAL | CVE-2026-75803 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: ChaCha20-Poly1305 and AES-OCB decryption with an empty |
| 4 | CRITICAL | CVE-2026-59873 | tar | 7.4.3 | 7.5.19 | – | node-tar: Decompression/parse DoS via unlimited input |
| 4 | CRITICAL | CVE-2026-59873 | tar | 7.4.3 | 7.5.19 | – | node-tar: Decompression/parse DoS via unlimited input |
| 4 | CRITICAL | CVE-2026-59873 | tar | 6.2.1 | 7.5.19 (anderer Versionszweig: Upgrade nötig) | – | node-tar: Decompression/parse DoS via unlimited input |
| 4 | CRITICAL | CVE-2026-85091 | zlib | 1.3.1-r2 | 1.3.2-r1 | – | zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow vulnerability in the gz |
| 4 | HIGH | CVE-2026-102276 | brace-expansion | 2.0.2 | 2.1.5 | – | brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustio |
| 4 | HIGH | CVE-2026-102278 | brace-expansion | 2.0.2 | 2.1.6 | – | brace-expansion: DoS via uncontrolled recursion on nested brace groups causing stack exhau |
| 4 | HIGH | CVE-2026-13149 | brace-expansion | 2.0.2 | 2.1.2 | – | brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups |
| 4 | HIGH | CVE-2026-14257 | brace-expansion | 2.0.2 | 2.1.3 | – | brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash |
| 4 | HIGH | CVE-2026-69152 | brace-expansion | 2.0.2 | 2.1.4 | – | brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitig |
| 4 | HIGH | CVE-2025-64756 | glob | 10.4.5 | 10.5.0 | – | glob CLI: Command injection via -c/--cmd executes matches with shell:true |
| 4 | HIGH | CVE-2026-69192 | ip-address | 9.0.5 | 10.3.1 (anderer Versionszweig: Upgrade nötig) | – | ip-address: Address4 decodes leading-zero octets as decimal while resolvers decode them as |
| 4 | HIGH | CVE-2026-14456 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: When an OpenSSL QUIC server (Listener SSL object) processes |
| 4 | HIGH | CVE-2026-14457 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: In a server or client configuration with RFC7250 Raw Public Keys (RPKs) |
| 4 | HIGH | CVE-2026-18798 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: QUIC server may double free QRX (QUIC record layer RX) object |
| 4 | HIGH | CVE-2026-28387 | libcrypto3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: An uncommon configuration of clients performing DANE TLSA-based |
| 4 | HIGH | CVE-2026-28388 | libcrypto3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: When a delta CRL that contains a Delta CRL Indicator extension |
| 4 | HIGH | CVE-2026-28389 | libcrypto3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: During processing of a crafted CMS EnvelopedData message |
| 4 | HIGH | CVE-2026-28390 | libcrypto3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: During processing of a crafted CMS EnvelopedData message |
| 4 | HIGH | CVE-2026-31790 | libcrypto3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: Applications using RSASVE key encapsulation to establish |
| 4 | HIGH | CVE-2026-34180 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: Parsing a crafted DER-encoded ASN.1 structure with a primitive |
| 4 | HIGH | CVE-2026-34181 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue Summary: The PKCS#12 file processing fails to perform sufficient input |
| 4 | HIGH | CVE-2026-34183 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: Remote peer may exhaust heap memory of the QUIC |
| 4 | HIGH | CVE-2026-42764 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: Receiving a QUIC initial packet with an invalid token may |
| 4 | HIGH | CVE-2026-45445 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: When an application drives an AES-OCB context through the |
| 4 | HIGH | CVE-2026-45447 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: A specially crafted PKCS#7 or S/MIME signed message could |
| 4 | HIGH | CVE-2026-54874 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: Receiving a DTLS record for a future epoch while a handshake |
| 4 | HIGH | CVE-2026-63072 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: OpenSSL CMS decryption sizes the key-unwrap output buffer based |
| 4 | HIGH | CVE-2026-63075 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: When OpenSSL processes QUIC traffic from a peer that repeatedly |
| 4 | HIGH | CVE-2026-63076 | libcrypto3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: OpenSSL CMP password based protection verification only |
| 4 | HIGH | CVE-2026-7383 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: A signed integer overflow when sizing the destination |
| 4 | HIGH | CVE-2026-9076 | libcrypto3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: When CMS password-based decryption (RFC 3211 / PWRI key unwrap) |
| 4 | HIGH | CVE-2026-14456 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: When an OpenSSL QUIC server (Listener SSL object) processes |
| 4 | HIGH | CVE-2026-14457 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: In a server or client configuration with RFC7250 Raw Public Keys (RPKs) |
| 4 | HIGH | CVE-2026-18798 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: QUIC server may double free QRX (QUIC record layer RX) object |
| 4 | HIGH | CVE-2026-28387 | libssl3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: An uncommon configuration of clients performing DANE TLSA-based |
| 4 | HIGH | CVE-2026-28388 | libssl3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: When a delta CRL that contains a Delta CRL Indicator extension |
| 4 | HIGH | CVE-2026-28389 | libssl3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: During processing of a crafted CMS EnvelopedData message |
| 4 | HIGH | CVE-2026-28390 | libssl3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: During processing of a crafted CMS EnvelopedData message |
| 4 | HIGH | CVE-2026-31790 | libssl3 | 3.5.5-r0 | 3.5.6-r0 | – | Issue summary: Applications using RSASVE key encapsulation to establish |
| 4 | HIGH | CVE-2026-34180 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: Parsing a crafted DER-encoded ASN.1 structure with a primitive |
| 4 | HIGH | CVE-2026-34181 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue Summary: The PKCS#12 file processing fails to perform sufficient input |
| 4 | HIGH | CVE-2026-34183 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: Remote peer may exhaust heap memory of the QUIC |
| 4 | HIGH | CVE-2026-42764 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: Receiving a QUIC initial packet with an invalid token may |
| 4 | HIGH | CVE-2026-45445 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: When an application drives an AES-OCB context through the |
| 4 | HIGH | CVE-2026-45447 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: A specially crafted PKCS#7 or S/MIME signed message could |
| 4 | HIGH | CVE-2026-54874 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: Receiving a DTLS record for a future epoch while a handshake |
| 4 | HIGH | CVE-2026-63072 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: OpenSSL CMS decryption sizes the key-unwrap output buffer based |
| 4 | HIGH | CVE-2026-63075 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: When OpenSSL processes QUIC traffic from a peer that repeatedly |
| 4 | HIGH | CVE-2026-63076 | libssl3 | 3.5.5-r0 | 3.5.8-r0 | – | Issue summary: OpenSSL CMP password based protection verification only |
| 4 | HIGH | CVE-2026-7383 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: A signed integer overflow when sizing the destination |
| 4 | HIGH | CVE-2026-9076 | libssl3 | 3.5.5-r0 | 3.5.7-r0 | – | Issue summary: When CMS password-based decryption (RFC 3211 / PWRI key unwrap) |
| 4 | HIGH | CVE-2026-26996 | minimatch | 9.0.5 | 9.0.6 | – | minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern |
| 4 | HIGH | CVE-2026-27903 | minimatch | 9.0.5 | 9.0.7 | – | minimatch has ReDoS: matchOne() combinatorial backtracking via multiple non-adjacent GLOBS |
| 4 | HIGH | CVE-2026-27904 | minimatch | 9.0.5 | 9.0.7 | – | minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expres |
| 4 | HIGH | CVE-2026-107891 | musl-utils | 1.2.5-r21 | 1.2.5-r24 | – | musl libc before 1.2.7, when an untrusted regular expression is used with regcomp, has mul |
| 4 | HIGH | CVE-2026-40200 | musl-utils | 1.2.5-r21 | 1.2.5-r23 | – | An issue was discovered in musl libc 0.7.10 through 1.2.6. Stack-based memory corruption c |
| 4 | HIGH | CVE-2026-9496 | pacote | 20.0.0 | 21.5.1 (anderer Versionszweig: Upgrade nötig) | – | pacote is vulnerable to Denial of Service (DoS) via the addGitSha function |
| 4 | HIGH | CVE-2026-9496 | pacote | 19.0.1 | 21.5.1 (anderer Versionszweig: Upgrade nötig) | – | pacote is vulnerable to Denial of Service (DoS) via the addGitSha function |
| 4 | HIGH | CVE-2026-33671 | picomatch | 4.0.2 | 4.0.4 | – | Picomatch has a ReDoS vulnerability via extglob quantifiers |
| 4 | HIGH | CVE-2026-48815 | sigstore | 3.1.0 | 4.1.1 (anderer Versionszweig: Upgrade nötig) | – | sigstore's `certificateOIDs` verification constraints are silently dropped and never enfor |
| 4 | HIGH | CVE-2026-23745 | tar | 7.4.3 | 7.5.3 | – | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient  |
| 4 | HIGH | CVE-2026-23745 | tar | 7.4.3 | 7.5.3 | – | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient  |
| 4 | HIGH | CVE-2026-23745 | tar | 6.2.1 | 7.5.3 (anderer Versionszweig: Upgrade nötig) | – | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient  |
| 4 | HIGH | CVE-2026-23950 | tar | 7.4.3 | 7.5.4 | – | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS |
| 4 | HIGH | CVE-2026-23950 | tar | 7.4.3 | 7.5.4 | – | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS |
| 4 | HIGH | CVE-2026-23950 | tar | 6.2.1 | 7.5.4 (anderer Versionszweig: Upgrade nötig) | – | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS |
| 4 | HIGH | CVE-2026-24842 | tar | 7.4.3 | 7.5.7 | – | node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal |
| 4 | HIGH | CVE-2026-24842 | tar | 7.4.3 | 7.5.7 | – | node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal |
| 4 | HIGH | CVE-2026-24842 | tar | 6.2.1 | 7.5.7 (anderer Versionszweig: Upgrade nötig) | – | node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal |
| 4 | HIGH | CVE-2026-26960 | tar | 7.4.3 | 7.5.8 | – | Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Ext |
| 4 | HIGH | CVE-2026-26960 | tar | 7.4.3 | 7.5.8 | – | Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Ext |
| 4 | HIGH | CVE-2026-26960 | tar | 6.2.1 | 7.5.8 (anderer Versionszweig: Upgrade nötig) | – | Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Ext |
| 4 | HIGH | CVE-2026-29786 | tar | 7.4.3 | 7.5.10 | – | tar has Hardlink Path Traversal via Drive-Relative Linkpath |
| 4 | HIGH | CVE-2026-29786 | tar | 7.4.3 | 7.5.10 | – | tar has Hardlink Path Traversal via Drive-Relative Linkpath |
| 4 | HIGH | CVE-2026-29786 | tar | 6.2.1 | 7.5.10 (anderer Versionszweig: Upgrade nötig) | – | tar has Hardlink Path Traversal via Drive-Relative Linkpath |
| 4 | HIGH | CVE-2026-31802 | tar | 7.4.3 | 7.5.11 | – | node-tar Symlink Path Traversal via Drive-Relative Linkpath |
| 4 | HIGH | CVE-2026-31802 | tar | 7.4.3 | 7.5.11 | – | node-tar Symlink Path Traversal via Drive-Relative Linkpath |
| 4 | HIGH | CVE-2026-31802 | tar | 6.2.1 | 7.5.11 (anderer Versionszweig: Upgrade nötig) | – | node-tar Symlink Path Traversal via Drive-Relative Linkpath |
| 4 | HIGH | CVE-2026-59874 | tar | 7.4.3 | 7.5.18 | – | node-tar: Negative tar entry size causes infinite loop in archive replace |
| 4 | HIGH | CVE-2026-59874 | tar | 7.4.3 | 7.5.18 | – | node-tar: Negative tar entry size causes infinite loop in archive replace |
| 4 | HIGH | CVE-2026-59874 | tar | 6.2.1 | 7.5.18 (anderer Versionszweig: Upgrade nötig) | – | node-tar: Negative tar entry size causes infinite loop in archive replace |
| 4 | HIGH | CVE-2026-73566 | tar | 7.4.3 | 7.5.21 | – | node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow D |
| 4 | HIGH | CVE-2026-73566 | tar | 7.4.3 | 7.5.21 | – | node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow D |
| 4 | HIGH | CVE-2026-73566 | tar | 6.2.1 | 7.5.21 (anderer Versionszweig: Upgrade nötig) | – | node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow D |
| 4 | HIGH | CVE-2026-22184 | zlib | 1.3.1-r2 | 1.3.2-r0 | – | zlib versions up to and including 1.3.1.2 include a global buffer overflow in the untgz ut |
| 4 | HIGH | CVE-2026-4738 | zlib | 1.3.1-r2 | 1.4-r0 | – | Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in O |

KEV: im Katalog aktiv ausgenutzter Schwachstellen der CISA (Known Exploited Vulnerabilities).

## Nicht automatisch geprüft – bitte gesondert prüfen

Host-Komponenten, PHP-Erweiterungen mit eigener Version und Bibliotheken ohne erkennbare Version. Für sie gibt es in OSV keine (eindeutigen) Paketdaten.

| Typ | Name | Version | Fundort | Genutzt von |
|---|---|---|---|---|
| host | linux-kernel | 6.18.44-fc-v310 | Host | Host |
| host | docker-engine | 29.9.2 | Host | Host |
| host | containerd | v2.4.2 | Host | Host |
| host | runc | 1.5.2 | Host | Host |
| host | docker-init | 0.19.0 | Host | Host |

## Anhang

### Komponenten (gesamt / von Diensten mit offenem Port genutzt)

| Typ | gesamt | genutzt | dev |
|---|---|---|---|
| host | 5 | 0 | 0 |
| npm | 215 | 2 | 0 |
| os-paket | 18 | 3 | 0 |
| runtime | 1 | 1 | 0 |
| runtime-lib | 21 | 21 | 0 |

### Container

```
ID:        38213bf1f5b2baa85538a83d5dc025fa7c42e731c01438cf386c79ee5b77f0ec
Gestartet: 2026-11-07T20:36:31.321776519Z
Kommando:  ["docker-entrypoint.sh"] ["node", "server.js"]
Mounts:    /home/user/container-security-scan/beispiele/umgebung/node->/app
Host:      Kernel 6.18.44-fc-v310
```

### Laufende Prozesse

```
PID                 USER                COMMAND
1581                root                node server.js
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

Keine gefunden.
