# Container-Scan: app-traefik

- Image: traefik:v3.6 (sha256:31267173a15b)  
- OS: Alpine Linux v3.24  
- Zeitpunkt: 2026-11-14 08:32  
- Scanner: container-security-scan 0.4.1  
- Datenbank: OSV, Stand 2026-11-14 07:57 UTC (daten)  
- Erfassung: OS-Pakete apk; Dateien find/tar im Container (inkl. 0 Volumes); Prozesse im Container (je Prozess-Benutzer)

## Ergebnis

**Warnung:** Weiterleitungen von traefik:80 nicht vollständig auswertbar (traefik: Konfiguration wird nicht ausgewertet) – Container in denselben Docker-Netzen gelten als möglicherweise öffentlich: app-node  
**Warnung:** Öffentlicher Dienst traefik:80 läuft als root (UID 0, ohne unprivilegierte Worker) – eine Lücke darin gibt root im Container; Benutzer setzen (user:, USER) oder non-root-Image  
**32 relevante Schwachstellen** (Kriterium: P1 CRITICAL, P1 HIGH, P2 CRITICAL; aktiv ausgenutzte (KEV) unabhängig von Priorität und Schweregrad; nur mit verfügbarem Fix)

- **CVE-2026-111497** (CRITICAL* KEV) in github.com/andybalholm/brotli v1.2.0 – behoben in 1.2.7 – genutzt von traefik:80 – **aktiv ausgenutzt** (KEV seit 2026-10-27)
- **CVE-2026-78663** (CRITICAL*) in golang.org/x/net v0.57.0 – behoben in 0.60.0 – genutzt von traefik:80
- **CVE-2026-39821** (CRITICAL*) in stdlib 1.26.5 – behoben in 1.26.6 – genutzt von traefik:80
- **CVE-2026-78663** (CRITICAL*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- **CVE-2026-116587** (HIGH) in github.com/go-jose/go-jose/v4 v4.1.4 – behoben in 4.1.6 – genutzt von traefik:80
- **CVE-2026-116591** (HIGH*) in github.com/klauspost/compress v1.18.7 – behoben in 1.20.2 – genutzt von traefik:80
- **CVE-2026-88004** (HIGH) in github.com/traefik/traefik/v3 v3.6.25 – behoben in 3.7.13 – genutzt von traefik:80
- **CVE-2026-88008** (HIGH) in github.com/traefik/traefik/v3 v3.6.25 – behoben in 3.7.13 – genutzt von traefik:80
- **CVE-2026-88009** (HIGH) in github.com/traefik/traefik/v3 v3.6.25 – behoben in 3.7.13 – genutzt von traefik:80
- **CVE-2026-73500** (HIGH*) in go.etcd.io/etcd/client/pkg/v3 v3.6.4 – behoben in 3.6.14 – genutzt von traefik:80
- **CVE-2026-56864** (HIGH*) in golang.org/x/mod v0.37.0 – behoben in 0.40.0 – genutzt von traefik:80
- **CVE-2026-56865** (HIGH*) in golang.org/x/mod v0.37.0 – behoben in 0.40.0 – genutzt von traefik:80
- **CVE-2026-78659** (HIGH*) in golang.org/x/net v0.57.0 – behoben in 0.60.0 – genutzt von traefik:80
- **CVE-2026-78660** (HIGH*) in golang.org/x/net v0.57.0 – behoben in 0.60.0 – genutzt von traefik:80
- **CVE-2026-78669** (HIGH*) in golang.org/x/net v0.57.0 – behoben in 0.60.0 – genutzt von traefik:80
- **CVE-2026-97032** (HIGH*) in golang.org/x/net v0.57.0 – behoben in 0.60.0 – genutzt von traefik:80
- **CVE-2026-84304** (HIGH) in google.golang.org/grpc v1.82.1 – behoben in 1.83.1 – genutzt von traefik:80
- **CVE-2026-84445** (HIGH) in google.golang.org/grpc v1.82.1 – behoben in 1.82.2 – genutzt von traefik:80
- **CVE-2026-33818** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.6 – genutzt von traefik:80
- **CVE-2026-46600** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.6 – genutzt von traefik:80
- **CVE-2026-56853** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.6 – genutzt von traefik:80
- **CVE-2026-56859** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.6 – genutzt von traefik:80
- **CVE-2026-56862** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.6 – genutzt von traefik:80
- **CVE-2026-56866** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- **CVE-2026-78659** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- **CVE-2026-78660** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- **CVE-2026-78667** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- **CVE-2026-78669** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- **CVE-2026-94439** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- **CVE-2026-94440** (HIGH*) in stdlib 1.26.5 – behoben in 1.26.9 – genutzt von traefik:80
- … weitere 2 in der Tabelle unten

**1 gefährliche Einstellungen des Containers** (eine Lücke im Container führt damit zu root auf dem Host; Kennung für die Ausnahmeliste, Paket = Containername)

- **CONF-SOCKET**: /var/run/docker.sock eingebunden als /var/run/docker.sock: Zugriff auf die Container-Laufzeit = root auf dem Host (auch schreibgeschützt)

Einstellungen der Webserver (Statusseiten, Verzeichnislisten): keine gezählt.

Nicht gezählt (wären sonst relevant):
- CVE-2026-88007 (CRITICAL) in github.com/traefik/traefik/v3 v3.6.25 – betrifft laut Titel nur Windows
- CVE-2026-56857 (CRITICAL*) in stdlib 1.26.5 – betrifft laut Titel nur Windows

Hinweis: 10 Befunde in P1 haben noch keinen Schweregrad (UNKNOWN) – bitte mit ansehen.

## Laufende Dienste

| Dienst | Programm | Ports / Konfiguration |
|---|---|---|
| traefik:80 | traefik  | Port 80/tcp (alle) veröffentlicht als 127.0.0.1:8081 (nur lokal – vermutlich hinter einem Reverse Proxy auf dem Host); Ziel aus Docker-Labels: Container app-node, Port 3000; Weiterleitungen nicht vollständig auswertbar (traefik: Konfiguration wird nicht ausgewertet) – Container in denselben Docker-Netzen gelten als möglicherweise öffentlich: app-node |

## Übersicht (Anzahl Befunde)

| Priorität | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
|---|---|---|---|---|---|
| P1 Dienst mit veröffentlichtem Port | 6 | 28 | 19 | 4 | 10 |
| P2 Dienst intern | 0 | 0 | 0 | 0 | 0 |
| P3 Prozess ohne Port | 0 | 0 | 0 | 0 | 0 |
| P4 nicht genutzt / dev | 5 | 17 | 2 | 0 | 0 |

## Befunde (89 von 91; P3/P4 nur CRITICAL/HIGH/KEV, alle mit --alle)

| P | Schwere | ID | Paket | Installiert | Behoben in | Genutzt von | Webadressen | Titel |
|---|---|---|---|---|---|---|---|---|
| 1 | CRITICAL* KEV | CVE-2026-111497 | github.com/andybalholm/brotli | v1.2.0 | 1.2.7 | traefik:80 | – | Excessive memory allocation when decompressing crafted streams in github.com/andybalholm/b |
| 1 | CRITICAL | CVE-2026-88007 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.13 | traefik:80 | – | [nicht gezählt: betrifft laut Titel nur Windows] Traefik HTTP/3 Backend NTLM Connection Reuse |
| 1 | CRITICAL* | CVE-2026-78663 | golang.org/x/net | v0.57.0 | 0.60.0 | traefik:80 | – | Double flow control refund on HTTP/2 server streams in net/http |
| 1 | CRITICAL* | CVE-2026-39821 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Invoking failure to reject ASCII-only Punycode-encoded labels in golang.org/x/net/idna |
| 1 | CRITICAL* | CVE-2026-56857 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | [nicht gezählt: betrifft laut Titel nur Windows] Root.Mkdir(All) can follow junctions out of the root on Windows in os |
| 1 | CRITICAL* | CVE-2026-78663 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | Double flow control refund on HTTP/2 server streams in net/http |
| 1 | HIGH | CVE-2026-116587 | github.com/go-jose/go-jose/v4 | v4.1.4 | 4.1.6 | traefik:80 | – | Go JOSE: DoS when parsing JWKs that contain RSA keys |
| 1 | HIGH* | CVE-2026-116591 | github.com/klauspost/compress | v1.18.7 | 1.20.2 | traefik:80 | – | Panic on two-block frames in github.com/klauspost/compress |
| 1 | HIGH | CVE-2026-88004 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.13 | traefik:80 | – | Traefik entrypoint header-name sanitization bypassed via request trailers |
| 1 | HIGH | CVE-2026-88008 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.13 | traefik:80 | – | Traefik: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')  |
| 1 | HIGH | CVE-2026-88009 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.13 | traefik:80 | – | Traefik: Rootless HTTP/1 request-target routes as "/" but is forwarded verbatim, bypassing |
| 1 | HIGH* | CVE-2026-73500 | go.etcd.io/etcd/client/pkg/v3 | v3.6.4 | 3.6.14 | traefik:80 | – | Unbounded TLS handshake goroutines in go.etcd.io/etcd/client/pkg/v3 |
| 1 | HIGH* | CVE-2026-56864 | golang.org/x/mod | v0.37.0 | 0.40.0 | traefik:80 | – | Ignore unrelated, unauthenticated hashes in Lookup in golang.org/x/mod/sumdb |
| 1 | HIGH* | CVE-2026-56865 | golang.org/x/mod | v0.37.0 | 0.40.0 | traefik:80 | – | Fix transparency log tile verification bypass in golang.org/x/mod/sumdb/tlog |
| 1 | HIGH* | CVE-2026-78659 | golang.org/x/net | v0.57.0 | 0.60.0 | traefik:80 | – | HTTP/2 server memory exhaustion due to Trailer headers in net/http |
| 1 | HIGH* | CVE-2026-78660 | golang.org/x/net | v0.57.0 | 0.60.0 | traefik:80 | – | HTTP/2 transport accepts malformed framing-related headers in net/http |
| 1 | HIGH* | CVE-2026-78669 | golang.org/x/net | v0.57.0 | 0.60.0 | traefik:80 | – | Excessive CPU consumption from repeated initial window changes in net/http |
| 1 | HIGH* | CVE-2026-97032 | golang.org/x/net | v0.57.0 | 0.60.0 | traefik:80 | – | HTTP/2 server crash due to HPACK encoder race in net/http |
| 1 | HIGH | CVE-2026-84304 | google.golang.org/grpc | v1.82.1 | 1.83.1 | traefik:80 | – | gRPC-Go: Heap Memory Exhaustion (OOM) via HTTP/2 DATA Frame Fragmentation |
| 1 | HIGH | CVE-2026-84445 | google.golang.org/grpc | v1.82.1 | 1.82.2 | traefik:80 | – | gRPC-Go xDS servers: Denial of Service (DoS) via crash due to missing `:authority` and `Ho |
| 1 | HIGH* | CVE-2026-33818 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Enforce maximum recursion depth in encoding/asn1 |
| 1 | HIGH* | CVE-2026-46600 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Parsing an invalid SVCB or HTTPS RR can panic in golang.org/x/net/dns/dnsmessage |
| 1 | HIGH* | CVE-2026-56853 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check in net/http |
| 1 | HIGH* | CVE-2026-56859 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Add recursion depth guard during decode in encoding/xml |
| 1 | HIGH* | CVE-2026-56862 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Limit handshake messages we are willing to accept post-handshake in crypto/tls |
| 1 | HIGH* | CVE-2026-56866 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | HTTP/1 client connection desynchronization after CONNECT rejection in net/http |
| 1 | HIGH* | CVE-2026-78659 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | HTTP/2 server memory exhaustion due to Trailer headers in net/http |
| 1 | HIGH* | CVE-2026-78660 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | HTTP/2 transport accepts malformed framing-related headers in net/http |
| 1 | HIGH* | CVE-2026-78667 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | Lack of limit on size of parsed Range headers in net/http |
| 1 | HIGH* | CVE-2026-78669 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | Excessive CPU consumption from repeated initial window changes in net/http |
| 1 | HIGH* | CVE-2026-94439 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | HTTP/1 server connection desynchronization after 2xx CONNECT response in net/http |
| 1 | HIGH* | CVE-2026-94440 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | Memory limit bypass when parsing MIME headers in net/textproto, mime/multipart |
| 1 | HIGH* | CVE-2026-97031 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | Reject malformed ECH outer extension references in crypto/tls |
| 1 | HIGH* | CVE-2026-97032 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | HTTP/2 server crash due to HPACK encoder race in net/http |
| 1 | MEDIUM | CVE-2026-116585 | github.com/go-jose/go-jose/v4 | v4.1.4 | 4.1.5 | traefik:80 | – | Go JOSE: Panic during CBC-HMAC processing |
| 1 | MEDIUM | CVE-2026-116586 | github.com/go-jose/go-jose/v4 | v4.1.4 | 4.1.5 | traefik:80 | – | Go JOSE: Panics in JSON parsing |
| 1 | MEDIUM | CVE-2026-88010 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.13 | traefik:80 | – | Traefik: BasicAuth singleflight coalescing reintroduces an unauthenticated username-enumer |
| 1 | MEDIUM | CVE-2026-88011 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.12 | traefik:80 | – | Traefik: ForwardAuth identity spoofing via dot-form header alias |
| 1 | MEDIUM | CVE-2026-88012 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.12 | traefik:80 | – | Traefik: respondingTimeouts.readTimeout is not applied to HTTP/3, leaving slow-body upload |
| 1 | MEDIUM | CVE-2026-88878 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.12 | traefik:80 | – | Traefik: respondingTimeouts.readTimeout is not applied to HTTP/3, leaving slow-body upload |
| 1 | MEDIUM | CVE-2026-88879 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.12 | traefik:80 | – | Traefik: ForwardAuth identity spoofing via dot-form header alias |
| 1 | MEDIUM | CVE-2026-81871 | go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc | v0.20.0 | 0.21.0 | traefik:80 | – | OpenTelemetry-Go: Log gRPC exporter ignores env TLS certs, bypassing mTLS/pinning |
| 1 | MEDIUM | CVE-2026-128085 | go.opentelemetry.io/otel/sdk | v1.44.0 | 1.47.0 | traefik:80 | – | opentelemetry-go: AttributeValueLengthLimit is fully bypassed by attribute values composed |
| 1 | MEDIUM | CVE-2026-128085 | go.opentelemetry.io/otel/sdk/log | v0.20.0 | 1.47.0 | traefik:80 | – | opentelemetry-go: AttributeValueLengthLimit is fully bypassed by attribute values composed |
| 1 | MEDIUM | CVE-2026-81872 | go.opentelemetry.io/otel/sdk/log | v0.20.0 | 0.21.0 | traefik:80 | – | OpenTelemetry-Go: BatchProcessor can busy-spin when export buffer is full |
| 1 | MEDIUM | CVE-2026-128085 | go.opentelemetry.io/otel/trace | v1.44.0 | 1.47.0 | traefik:80 | – | opentelemetry-go: AttributeValueLengthLimit is fully bypassed by attribute values composed |
| 1 | MEDIUM | CVE-2026-84303 | google.golang.org/grpc | v1.82.1 | 1.83.1 | traefik:80 | – | gRPC-Go: xDS RBAC HTTP Filter bypass via mixed-case Header Matching and gRFC A41 validatio |
| 1 | MEDIUM | CVE-2026-54462 | knative.dev/pkg | v0.0.0-20241021183759-9b9d535af5ad | 0.0.0-20260531000007-52dbd5ece63f | traefik:80 | – | knative.dev/pkg admission webhooks allow unbounded request-body memory exhaustion |
| 1 | MEDIUM* | CVE-2026-111943 | stdlib | 1.26.5 | 1.26.10 | traefik:80 | – | Distrust compromised intermediate certificates in crypto/x509 |
| 1 | MEDIUM* | CVE-2026-56858 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Fix Javascript regexp context tracking in html/template |
| 1 | MEDIUM* | CVE-2026-56860 | stdlib | 1.26.5 | 1.26.6 | traefik:80 | – | Avoid quadratic complexity in resolvePath in net/url |
| 1 | MEDIUM* | CVE-2026-94448 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | Reset context tracking on consecutive template expressions in html/template |
| 1 | MEDIUM* | CVE-2026-97030 | stdlib | 1.26.5 | 1.26.9 | traefik:80 | – | Recognize yield as regexp preceder keyword in html/template |
| 1 | LOW | CVE-2026-81870 | go.opentelemetry.io/otel/exporters/otlp/otlptrace | v1.44.0 | 1.45.0 | traefik:80 | – | OpenTelemetry-Go: Exporter config logging may leak endpoint URLs in info logs |
| 1 | LOW | CVE-2026-81870 | go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc | v1.44.0 | 1.45.0 | traefik:80 | – | OpenTelemetry-Go: Exporter config logging may leak endpoint URLs in info logs |
| 1 | LOW | CVE-2026-81870 | go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp | v1.44.0 | 1.45.0 | traefik:80 | – | OpenTelemetry-Go: Exporter config logging may leak endpoint URLs in info logs |
| 1 | LOW | CVE-2026-81870 | go.opentelemetry.io/otel/sdk | v1.44.0 | 1.45.0 | traefik:80 | – | OpenTelemetry-Go: Exporter config logging may leak endpoint URLs in info logs |
| 1 | UNKNOWN | CVE-2026-53622 | github.com/traefik/traefik/v3 | v3.6.25 | 3.7.3 | traefik:80 | – | Traefik: HTTP/3 mTLS bypass via exact SNI TLSOptions lookup for wildcard and mixed-case ho |
| 1 | UNKNOWN | GO-2026-4950 | github.com/valyala/fasthttp | v1.69.0 | 1.70.0 | traefik:80 | – | Authorization bypass via double-encoded paths in github.com/valyala/fasthttp |
| 1 | UNKNOWN | CVE-2026-56854 | golang.org/x/crypto | v0.54.0 | 0.55.0 | traefik:80 | – | Source-address critical option not enforced for non-public-key auth callbacks in golang.or |
| 1 | UNKNOWN | CVE-2026-56855 | golang.org/x/crypto | v0.54.0 | 0.56.0 | traefik:80 | – | Prevent DoS on deadlocked established channel in golang.org/x/crypto/ssh |
| 1 | UNKNOWN | CVE-2026-78662 | golang.org/x/crypto | v0.54.0 | 0.56.0 | traefik:80 | – | Prevent DoS on deadlocked undecided channel in golang.org/x/crypto/ssh |
| 1 | UNKNOWN | GO-2026-5932 | golang.org/x/crypto | v0.54.0 | 0.58.1-0.20261009181718-2f1f834330b2 | traefik:80 | – | The golang.org/x/crypto/openpgp package is unmaintained, unsafe by design, and has known s |
| 1 | UNKNOWN | CVE-2026-78661 | golang.org/x/net | v0.57.0 | 0.62.0 | traefik:80 | – | Avoid quadratic complexity when coalescing text nodes in html in golang.org/x/net |
| 1 | UNKNOWN | CVE-2026-97045 | golang.org/x/net | v0.57.0 | 0.62.0 | traefik:80 | – | Check all ancestor namespace transitions when rendering raw text in html in golang.org/x/n |
| 1 | UNKNOWN | CVE-2026-56851 | golang.org/x/text | v0.40.0 | 0.41.0 | traefik:80 | – | Panic parsing crafted input in x/text/secure/precis in golang.org/x/text |
| 1 | UNKNOWN | CVE-2026-97054 | stdlib | 1.26.5 | 1.26.11 | traefik:80 | – | HTTP/1 server crash due to MaxBytesReader header race in net/http |
| 4 | CRITICAL | CVE-2026-63073 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: OpenSSL CMP response validation passed an unexpected response |
| 4 | CRITICAL | CVE-2026-75803 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: ChaCha20-Poly1305 and AES-OCB decryption with an empty |
| 4 | CRITICAL | CVE-2026-63073 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: OpenSSL CMP response validation passed an unexpected response |
| 4 | CRITICAL | CVE-2026-75803 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: ChaCha20-Poly1305 and AES-OCB decryption with an empty |
| 4 | CRITICAL | CVE-2026-85091 | zlib | 1.3.2-r0 | 1.3.2-r1 | – | – | zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow vulnerability in the gz |
| 4 | HIGH | CVE-2026-14456 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: When an OpenSSL QUIC server (Listener SSL object) processes |
| 4 | HIGH | CVE-2026-14457 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: In a server or client configuration with RFC7250 Raw Public Keys (RPKs) |
| 4 | HIGH | CVE-2026-18798 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: QUIC server may double free QRX (QUIC record layer RX) object |
| 4 | HIGH | CVE-2026-54874 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: Receiving a DTLS record for a future epoch while a handshake |
| 4 | HIGH | CVE-2026-63072 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: OpenSSL CMS decryption sizes the key-unwrap output buffer based |
| 4 | HIGH | CVE-2026-63075 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: When OpenSSL processes QUIC traffic from a peer that repeatedly |
| 4 | HIGH | CVE-2026-63076 | libcrypto3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: OpenSSL CMP password based protection verification only |
| 4 | HIGH | CVE-2026-14456 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: When an OpenSSL QUIC server (Listener SSL object) processes |
| 4 | HIGH | CVE-2026-14457 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: In a server or client configuration with RFC7250 Raw Public Keys (RPKs) |
| 4 | HIGH | CVE-2026-18798 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: QUIC server may double free QRX (QUIC record layer RX) object |
| 4 | HIGH | CVE-2026-54874 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: Receiving a DTLS record for a future epoch while a handshake |
| 4 | HIGH | CVE-2026-63072 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: OpenSSL CMS decryption sizes the key-unwrap output buffer based |
| 4 | HIGH | CVE-2026-63075 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: When OpenSSL processes QUIC traffic from a peer that repeatedly |
| 4 | HIGH | CVE-2026-63076 | libssl3 | 3.5.7-r0 | 3.5.8-r0 | – | – | Issue summary: OpenSSL CMP password based protection verification only |
| 4 | HIGH | CVE-2026-107891 | musl | 1.2.6-r2 | 1.2.6-r3 | – | – | musl libc before 1.2.7, when an untrusted regular expression is used with regcomp, has mul |
| 4 | HIGH | CVE-2026-107891 | musl-utils | 1.2.6-r2 | 1.2.6-r3 | – | – | musl libc before 1.2.7, when an untrusted regular expression is used with regcomp, has mul |
| 4 | HIGH | CVE-2026-4738 | zlib | 1.3.2-r0 | 1.4-r0 | – | – | Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in O |

\* Schweregrad aus einer anderen Quelle zur selben CVE (ALPINE-CVE-2026-111943, ALPINE-CVE-2026-116591, ALPINE-CVE-2026-39821, BIT-brotli-2026-111497, BIT-etcd-2026-73500, …), da der zutreffende Eintrag keinen nennt.

KEV: im Katalog aktiv ausgenutzter Schwachstellen der CISA (Known Exploited Vulnerabilities).

## Nicht automatisch geprüft – bitte gesondert prüfen

Host-Komponenten, PHP-Erweiterungen mit eigener Version und Bibliotheken ohne erkennbare Version. Für sie gibt es in OSV keine (eindeutigen) Paketdaten.

| Typ | Name | Version | Fundort | Genutzt von |
|---|---|---|---|---|
| host | linux-kernel | 6.18.44-fc-v470 | Host | Host |
| host | docker-engine | 29.9.2 | Host | Host |
| host | containerd | v2.4.2 | Host | Host |
| host | runc | 1.5.2 | Host | Host |
| host | docker-init | 0.19.0 | Host | Host |

## Anhang

### Komponenten (gesamt / von Diensten mit offenem Port genutzt)

| Typ | gesamt | genutzt | dev |
|---|---|---|---|
| go | 351 | 351 | 0 |
| host | 5 | 0 | 0 |
| os-paket | 18 | 0 | 0 |

### Container

```
ID:        f55f3412c4eaf9c9a578d21b0830f55474d0a1299e5ba8d9f07ab747fa8bdc1a
Gestartet: 2026-11-14T08:31:30.99450844Z
Kommando:  ["/entrypoint.sh"] ["--providers.docker=true", "--providers.docker.exposedbydefault=false", "--entrypoints.web.address=:80"]
Mounts:    /var/run/docker.sock->/var/run/docker.sock
Host:      Kernel 6.18.44-fc-v470
```

### Laufende Prozesse

```
PID                 USER                COMMAND
931                 root                traefik traefik --providers.docker=true --providers.docker.exposedbydefault=false --entrypoints.web.address=:80
3706                nobody              timeout 50 python -I -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
3737                nobody              timeout 50 python -E -s -S -c import json, os, platform, sys r = {"exe": os.path.realpath(sys.executable), "version": platform.python_version(), "libs": {}} try: import ssl n, v = ssl.OPENSSL_VERSION.split()[:2] r["libs"][n.lower()] = v except Exception: pass for mod, name, attr in (("sqlite3", "sqlite", "sqlite_version"), ("pyexpat", "expat", "EXPAT_VERSION"), ("zlib", "zlib", "ZLIB_RUNTIME_VERSION")): try: r["libs"][name] = str(getattr(__import__(mod), attr)).replace("expat_", "") except Exception: pass sys.stdout.write(json.dumps(r))
3767                nobody              timeout 50 nginx -v
3797                nobody              timeout 50 httpd -v
3827                nobody              timeout 50 apache2 -v
3857                nobody              timeout 50 java -XX:-UsePerfData -version
3887                nobody              timeout 50 mariadbd --version
3917                nobody              timeout 50 mysqld --version
3947                nobody              timeout 50 postgres --version
```

### Prozesse mit gelöschten (veralteten) Dateien im Speicher

Keine gefunden.
