# uhttps

A **tiny, multi-threaded HTTPS server** for **macOS, Linux, and Windows**, released under **GPLv2**.

`uhttps` is designed to be **portable**, **secure**, and **lightweight**, with a **very small footprint** and **high performance**.  
It is written in **pure C**, using only portable file and socket APIs.

---

## Why uhttps?

- Need to spin up an **HTTP/HTTPS server in seconds** without complex configuration?  
- Curious about socket programming, IPv4/IPv6 agnostic applications, or thread pool management?  
- Looking for a minimal, embeddable web server with TLS support?  

 **uhttps is made for you!**

---
## Related Project

If you only need **plain HTTP** (no TLS/HTTPS), check out  
👉 [uweb](https://github.com/PJO2/uweb) — the original tiny HTTP server this project is based on.  

- Even smaller footprint  
- Same command-line interface  
- Ideal for quick tests, embedded use, or environments where TLS is handled upstream (reverse proxy, load balancer,
---

## Usage

```text
uhttps [-4|-6] [-p port] [-d dir] [-i addr] [-c type|-ct|-cb] [-g msec] [-s max] [-v] [-x file] [-e extension]
       [--tls] [--cert file] [--key file] [--redirect-http]
```

### General options

- `-4` Use IPv4 only  
- `-6` Use IPv6 only  
- `-c` Define content-type for unknown files  
   - Default: reject unregistered types  
   - `-ct` = `-c "text/plain"`  
   - `-cb` = `-c "application/octet-stream"`  
- `-d` Set base directory for HTML content (default: current directory)  
- '-e' Add default file extension (-e 'html' will serve 'file' as 'file.html' if 'file' is not found)
- `-g` Delay transfers by *x* ms between frames (simulate slow link)  
- `-i` Bind server to a specific IP address  
- `-p` Change port (default: `8080` for HTTP, `8443` for HTTPS)  
   - Ports < 1024 require root/administrator privileges  
- `-s` Set maximum simultaneous connections (default: `1024`)  
- `-v` Verbose output  
- `-x` Default page for a directory (default: `index.html`)  

### TLS / HTTPS options

- `--tls` Enable HTTPS support  
- `--cert <file>` Path to server certificate (PEM format)  
- `--key <file>` Path to private key (PEM format)  
- `--redirect-http` Redirect plain HTTP (`http://`) requests to HTTPS (`https://`)  

---

## Build & Run

### macOS

First build and install the ssl library from the source code
```bash
curl -L -o openssl-3.6.0.tgz https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz
tar zxvf openssl-3.6.0.tgz
cd openssl-openssl-3.6.0
./Configure
make
# make test (optional)
make install
```

Then build and run uhttps :

### Linux / macOS

```bash
git clone https://github.com/PJO2/uhttps
cd uhttps
make
./uhttps --tls --cert server.crt --key server.key -v
```

### Windows

Use the prebuilt binaries:  

```powershell
git clone https://github.com/PJO2/uhttps
uhttps\WindowsBinaries\uhttps64-nodll.exe --tls --cert server.crt --key server.key -v
```

## Windows Binaries

Prebuilt Windows executables are available in the [`WindowsBinaries`](https://github.com/PJO2/uhttps/tree/main/WindowsBinaries) folder.  
Two editions are provided:

### 🔹 Dynamic build
- Much **smaller executable size**  
- Requires the **Microsoft Visual C++ Runtime** (`vcruntime140.dll` or newer)  
- Requires **OpenSSL DLLs** (`libssl-*.dll`, `libcrypto-*.dll`) to be present in the same directory or in the system path  
- Recommended if you want a minimal footprint and already have the runtime/dlls installed  

### 🔹 Static build
- Larger executable size  
- **Self-contained**: no dependency on external DLLs (Visual C++ runtime or OpenSSL)  
- Recommended for maximum portability (drop & run)  

👉 If in doubt, start with the **static build** for easiest usage.

A **Build procedure using Visual Studio** is included if you prefer to build your own binaries.

---

## Quick Test

Generate a **self-signed certificate** (example for Linux/macOS):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365
```

Start the server with HTTPS:

```bash
./uhttps --tls --cert server.crt --key server.key -v
```

Open your browser at:  

👉 [https://127.0.0.1:8443/](https://127.0.0.1:8443/)  

*(you may need to accept the self-signed certificate in your browser)*

---

## Advanced Example: HTTP + HTTPS with Redirect

A common setup is to serve **HTTP on port 8080** and automatically redirect all traffic to **HTTPS on port 8443**.

1. Create certificate and key (if not done yet):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365
```

2. Run uhttps with both HTTP and HTTPS:

```bash
# HTTP server on port 8080 + HTTPS server on port 8443 with redirect
./uhttps -p 8080 --tls --cert server.crt --key server.key --redirect-http -v
```

3. Test:

- Visiting [http://127.0.0.1:8080/](http://127.0.0.1:8080/) will redirect to  
  [https://127.0.0.1:8443/](https://127.0.0.1:8443/).  
- All secure content will be served on HTTPS.

---

## License

Released under the **GNU General Public License v2 (GPLv2)**.
