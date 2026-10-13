#!/usr/bin/env python3
"""Auto-deploy lucky-boot watcher for the PS5 13.60 (10.0.0.x).

Polls the LAN for elfldr (9021) hosts. For each NEW host it:
  1. queries firmware via fwquery.elf (read-only, non-destructive),
  2. if 13.60 (0x13600007), sends hvwatch.elf (send-and-forget, ~8 min scan),
  3. polls /mnt/usb0/hvwatch/RESULT.txt over FTP for LUCKY/NOT-LUCKY,
  4. appends a timestamped line to hvwatch_log.txt.
Skips 10.0.0.x (11.60 Pro) outright. Loops forever.
"""
import socket, time, ftplib, os, datetime, concurrent.futures, threading

BASE = os.path.dirname(os.path.abspath(__file__))
HVWATCH = os.path.join(BASE, "hvwatch_fast.elf")
FWQUERY = os.path.join(BASE, "fwquery.elf")
KLOGSRV = os.path.join(BASE, "klogsrv.elf")
HVFULLDUMP = os.path.join(BASE, "hvfulldump.elf")
LOG = os.path.join(BASE, "hvwatch_log.txt")

SKIP_IPS = {"10.0.0.x"}          # 11.60 Pro — never touch
FW_TARGET = 0x13600007             # 13.60

def log(msg):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def port_open(ip, port, timeout=0.8):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def lan_elfldr_hosts():
    hosts = []
    def chk(ip):
        if ip in SKIP_IPS:
            return
        if port_open(ip, 9021):
            hosts.append(ip)
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        futs = [ex.submit(chk, "10.0.0.%d" % i) for i in range(1, 255)]
        for f in concurrent.futures.as_completed(futs):
            f.result()
    return hosts

def send_elf(ip, path, timeout=20):
    data = open(path, "rb").read()
    s = socket.create_connection((ip, 9021), timeout=10)
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
    except Exception:
        pass
    s.close()
    return out.decode("utf-8", "replace")

def query_fw(ip):
    out = send_elf(ip, FWQUERY, timeout=15)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("fw="):
            try:
                return int(line[3:].strip(), 16)
            except Exception:
                return None
    return None

def ftp_get(ip, path):
    try:
        f = ftplib.FTP()
        f.connect(ip, 2121, timeout=6)
        f.login("anonymous", "anonymous@")
        r = []
        f.retrlines("RETR " + path, r.append)
        f.quit()
        return "\n".join(r)
    except Exception as e:
        return "ERR %s" % e

def capture_klog(ip, path, stop, duration=700):
    with open(path, "wb") as f:
        end = time.time() + duration
        while not stop.is_set() and time.time() < end:
            try:
                s = socket.socket()
                s.settimeout(8)
                s.connect((ip, 3232))
                while not stop.is_set() and time.time() < end:
                    try:
                        d = s.recv(65536)
                        if not d:
                            break
                        f.write(d)
                    except socket.timeout:
                        continue
                s.close()
            except Exception:
                time.sleep(2)


def full_dump(ip):
    try:
        f = ftplib.FTP(); f.connect(ip, 2121, timeout=6); f.login("anonymous", "anonymous@")
        try: f.delete("/mnt/usb0/hvfulldump/DONE.txt")
        except Exception: pass
        f.quit()
    except Exception:
        pass
    send_elf(ip, HVFULLDUMP, timeout=5)
    for i in range(40):
        time.sleep(20)
        done = ftp_get(ip, "/mnt/usb0/hvfulldump/DONE.txt")
        if done.startswith("dumped="):
            log("%s: full dump %s" % (ip, done.strip()))
            return
        if not port_open(ip, 9021, timeout=2):
            log("%s: elfldr dropped during full dump" % ip)
            return
    log("%s: full dump timed out" % ip)


def pull_all(ip):
    outdir = os.path.join(BASE, "lucky_%s" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(outdir, exist_ok=True)
    f = ftplib.FTP(); f.connect(ip, 2121, timeout=10); f.login("anonymous", "anonymous@")
    n = 0
    for remote_dir in ["/mnt/usb0/hvwatch", "/mnt/usb0/hvfulldump"]:
        try:
            names = [x for x, _ in f.mlsd(remote_dir) if x.endswith(".bin")]
            for name in names:
                with open(os.path.join(outdir, name), "wb") as fh:
                    f.retrbinary("RETR %s/%s" % (remote_dir, name), fh.write)
                n += 1
        except Exception as e:
            log("%s: pull %s err %r" % (ip, remote_dir, e))
    f.quit()
    log("%s: pulled %d files to %s" % (ip, n, outdir))


def watch_boot(ip):
    fw = query_fw(ip)
    if fw is None:
        log("%s: fw-query failed (skipping)" % ip)
        return
    if fw != FW_TARGET:
        log("%s: fw=0x%08x (not 13.60, skipping)" % (ip, fw))
        return
    log("%s: fw=0x%08x confirmed 13.60 -> klogsrv + hvwatch" % (ip, fw))

    # deploy klogsrv (send-and-forget), then start capturing the klog
    send_elf(ip, KLOGSRV, timeout=5)
    time.sleep(4)
    klog_path = os.path.join(BASE, "klog_%s.log" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    stop = threading.Event()
    kt = threading.Thread(target=capture_klog, args=(ip, klog_path, stop), daemon=True)
    kt.start()

    # clear stale RESULT, then deploy hvwatch (send-and-forget)
    try:
        f = ftplib.FTP()
        f.connect(ip, 2121, timeout=6)
        f.login("anonymous", "anonymous@")
        f.delete("/mnt/usb0/hvwatch/RESULT.txt")
        f.quit()
    except Exception:
        pass
    send_elf(ip, HVWATCH, timeout=5)

    for i in range(40):               # up to ~13 min
        time.sleep(20)
        res = ftp_get(ip, "/mnt/usb0/hvwatch/RESULT.txt")
        if res.startswith("dumps="):
            log("%s: RESULT = %s" % (ip, res.strip()))
            try:
                ndumps = int(res.strip().split("=", 1)[1].split()[0])
            except Exception:
                ndumps = 0
            if ndumps > 0:
                log("%s: LUCKY (%d clusters) -> full dump + auto-pull" % (ip, ndumps))
                full_dump(ip)
                pull_all(ip)
            break
        if not port_open(ip, 9021, timeout=2):
            log("%s: elfldr dropped before RESULT (reboot?)" % ip)
            break
    else:
        log("%s: timed out waiting for RESULT" % ip)

    stop.set()
    time.sleep(1)
    ksize = os.path.getsize(klog_path) if os.path.exists(klog_path) else 0
    log("%s: klog saved to %s (%d bytes)" % (ip, klog_path, ksize))

def main():
    log("=== auto-deploy watcher started ===")
    seen = set()
    while True:
        try:
            hosts = set(lan_elfldr_hosts())
            for h in sorted(hosts):
                if h in seen:
                    continue
                seen.add(h)
                log("%s: new elfldr host detected" % h)
                watch_boot(h)
            seen &= hosts
        except Exception as e:
            log("loop error: %r" % e)
        time.sleep(20)

if __name__ == "__main__":
    main()
