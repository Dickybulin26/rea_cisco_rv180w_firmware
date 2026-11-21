use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};

const THTTPD_WRAPPER: &str = r#"#!/bin/sh
# RV180W Modern TLS Mod wrapper for /pfrm2.0/bin/thttpd
# Runs original thttpd for HTTP on port 80 and delegates HTTPS to modern-tls-proxy (TLS 1.2/1.3).

HTTP_PORT="80"
HTTPS_PORT="443"
ENABLE_HTTPS="0"
FILTERED_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -p)
            HTTP_PORT="$2"
            FILTERED_ARGS="$FILTERED_ARGS -p $2"
            shift 2
            ;;
        -sport)
            HTTPS_PORT="$2"
            ENABLE_HTTPS="1"
            shift 2
            ;;
        -cert|-key|-cafile|-cadir|-crlfile|-crldir|-rand)
            shift 2
            ;;
        -E)
            ENABLE_HTTPS="1"
            shift 1
            ;;
        *)
            FILTERED_ARGS="$FILTERED_ARGS $1"
            shift 1
            ;;
    esac
done

# Start original thttpd in HTTP-only mode
# shellcheck disable=SC2086
/pfrm2.0/bin/thttpd.orig $FILTERED_ARGS
THTTPD_RC=$?

# Ensure modern-tls-proxy handles HTTPS (TLS 1.2/1.3) cleanly
if [ "$ENABLE_HTTPS" = "1" ] || [ -x /pfrm2.0/bin/modern-tls-proxy ]; then
    if [ -f /var/run/modern-tls-proxy.pid ]; then
        OLD_PID=`cat /var/run/modern-tls-proxy.pid 2>/dev/null`
        if [ -n "$OLD_PID" ]; then
            kill "$OLD_PID" 2>/dev/null
        fi
    fi
    /pfrm2.0/bin/modern-tls-proxy \
        --listen "0.0.0.0:${HTTPS_PORT}" \
        --backend "127.0.0.1:${HTTP_PORT}" \
        --cert-dir /data/certs \
        --san-ip 192.168.1.1 \
        --max-conns 16 \
        --pid-file /var/run/modern-tls-proxy.pid \
        >/var/log/modern-tls-proxy.log 2>&1 &
fi

exit $THTTPD_RC
"#;

const THTTPD_KEEPALIVE_PATCHED: &str = r#"#!/bin/sh
# RV180W Modern TLS Mod watchdog
while [ 1 ]
do
psop=`pidof thttpd.orig`
totalProcess=`echo $psop | wc -w`
if [ $totalProcess -lt 1 ] ;then
sqlite3 /tmp/system.db << SQL_ENTR_TAG_1;
.timeout 1000;
BEGIN;
update enforceHTTPS set _ROWID_= 1 where _ROWID_= 1;
update httpsmgmt set _ROWID_= 1 where _ROWID_= 1;
COMMIT;
SQL_ENTR_TAG_1
fi

proxyPid=`pidof modern-tls-proxy`
if [ -z "$proxyPid" ] && [ -x /pfrm2.0/bin/modern-tls-proxy ]; then
    /pfrm2.0/bin/modern-tls-proxy \
        --listen 0.0.0.0:443 \
        --backend 127.0.0.1:80 \
        --cert-dir /data/certs \
        --san-ip 192.168.1.1 \
        --max-conns 16 \
        --pid-file /var/run/modern-tls-proxy.pid \
        >/var/log/modern-tls-proxy.log 2>&1 &
fi

linkMonitorProcess=`pidof linkMonitor`
if [ -z "$linkMonitorProcess" ];then
    /pfrm2.0/bin/linkMonitor 5 3 2> /dev/null
fi
sleep 30
done
"#;

const MODERN_BDETECT_JS: &str = r#"/* RV180W Modern Browser Compatibility Patch */
var d,dom,ie,ie4,ie5x,moz,mac,win,lin,old,ie5mac,ie5xwin,op,konq,saf,n,na,nua;
d=document;n=navigator;na=n.appVersion||"";nua=n.userAgent||"";
win=(na.indexOf("Win")!=-1||nua.indexOf("Windows")!=-1);
mac=(na.indexOf("Mac")!=-1||nua.indexOf("Macintosh")!=-1);
lin=(na.indexOf("Linux")!=-1||nua.indexOf("Linux")!=-1);
dom=!!(d.getElementById);
op=(nua.indexOf("Opera")!=-1);
konq=(nua.indexOf("Konqueror")!=-1);
saf=(nua.indexOf("Safari")!=-1);
moz=(nua.indexOf("Gecko")!=-1&&!saf&&!konq);
ie=(nua.indexOf("MSIE")!=-1&&!op);
ie4=(ie&&!dom);
ie5x=(ie&&dom);
ie5mac=(mac&&ie5x);
ie5xwin=(win&&ie5x);
old=false;
"#;

const MODERN_AJAX_REQUESTS_JS: &str = r#"/* RV180W Modern Browser Compatibility Patch */
function getUserInfo(){
    var c=document.getElementById("lblLoggedinUser");
    if(!c||c.innerHTML!=""){return;}
    var a=null;
    try{a=new XMLHttpRequest();}
    catch(b){
        try{a=new ActiveXObject("Msxml2.XMLHTTP");}
        catch(b2){
            try{a=new ActiveXObject("Microsoft.XMLHTTP");}
            catch(b3){return false;}
        }
    }
    a.onreadystatechange=function(){
        if(a.readyState===4&&a.status===200){
            c.innerHTML=a.responseText+" ";
        }
    };
    a.open("GET","getUser.htm?time="+Date.now(),true);
    a.send(null);
}
"#;

const MOD_STATUS_CGI: &str = r#"#!/bin/sh
echo "Content-Type: application/json; charset=utf-8"
echo "Cache-Control: no-store"
echo ""
UPTIME_VAL=`cat /proc/uptime 2>/dev/null | awk '{print $1}'`
LOAD_VAL=`cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}'`
MEM_TOTAL=`awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null`
MEM_FREE=`awk '/MemFree/ {print $2}' /proc/meminfo 2>/dev/null`
KERNEL_VAL=`uname -r 2>/dev/null`
PROXY_PID=`pidof modern-tls-proxy 2>/dev/null`
HTTPD_PID=`pidof thttpd.orig 2>/dev/null`
cat <<EOF
{
  "firmware": "RV180W-1.0.5.4-MOD",
  "tls_proxy": "rustls TLS 1.2/1.3",
  "kernel": "${KERNEL_VAL:-unknown}",
  "uptime_sec": "${UPTIME_VAL:-0}",
  "loadavg": "${LOAD_VAL:-0 0 0}",
  "mem_total_kb": ${MEM_TOTAL:-0},
  "mem_free_kb": ${MEM_FREE:-0},
  "proxy_pid": "${PROXY_PID:-stopped}",
  "thttpd_pid": "${HTTPD_PID:-stopped}"
}
EOF
"#;

const MOD_STATUS_HTM: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cisco RV180W Modern TLS Mod - System Diagnostics</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }
  .card { max-width: 720px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 1.5rem 2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.35); }
  h1 { margin-top: 0; font-size: 1.35rem; color: #38bdf8; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin: 1.25rem 0; }
  .metric { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 0.9rem 1rem; }
  .label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }
  .value { font-size: 1.15rem; font-weight: 600; margin-top: 0.35rem; color: #f8fafc; }
  .actions { display: flex; gap: 0.75rem; margin-top: 1.25rem; }
  a, button { background: #0284c7; color: #fff; border: 0; border-radius: 6px; padding: 0.55rem 1rem; text-decoration: none; cursor: pointer; font-size: 0.9rem; }
  a:hover, button:hover { background: #0369a1; }
</style>
</head>
<body>
<div class="card">
  <h1>Cisco RV180W Modern TLS Mod &mdash; Live Diagnostics</h1>
  <div class="grid" id="metrics">
    <div class="metric"><div class="label">Firmware</div><div class="value" id="m-fw">Loading...</div></div>
    <div class="metric"><div class="label">TLS Engine</div><div class="value" id="m-tls">-</div></div>
    <div class="metric"><div class="label">Kernel</div><div class="value" id="m-kern">-</div></div>
    <div class="metric"><div class="label">Load Average</div><div class="value" id="m-load">-</div></div>
    <div class="metric"><div class="label">Memory (Free / Total)</div><div class="value" id="m-mem">-</div></div>
    <div class="metric"><div class="label">Daemons (Proxy / HTTP)</div><div class="value" id="m-pids">-</div></div>
  </div>
  <div class="actions">
    <button type="button" onclick="refreshStats()">Refresh</button>
    <a href="/index.htm">Back to RV180W Admin Dashboard</a>
  </div>
</div>
<script>
async function refreshStats() {
  try {
    const r = await fetch('/modStatus.cgi', { cache: 'no-store' });
    const d = await r.json();
    document.getElementById('m-fw').textContent = d.firmware;
    document.getElementById('m-tls').textContent = d.tls_proxy;
    document.getElementById('m-kern').textContent = d.kernel;
    document.getElementById('m-load').textContent = d.loadavg;
    document.getElementById('m-mem').textContent = d.mem_free_kb + ' KB / ' + d.mem_total_kb + ' KB';
    document.getElementById('m-pids').textContent = d.proxy_pid + ' / ' + d.thttpd_pid;
  } catch (e) {
    document.getElementById('m-fw').textContent = 'Error: ' + e;
  }
}
refreshStats();
</script>
</body>
</html>
"#;

pub struct PatchReport {
    pub proxy_size_bytes: u64,
    pub patched_files: Vec<String>,
}

pub fn patch_rootfs(work_dir: &Path, proxy_bin_path: &Path) -> Result<PatchReport> {
    let root = work_dir.join("squashfs-root");
    if !root.is_dir() {
        bail!(
            "squashfs-root not found at {} — run `unpack` first",
            root.display()
        );
    }
    if !proxy_bin_path.is_file() {
        bail!(
            "ARM32 proxy binary not found at {}",
            proxy_bin_path.display()
        );
    }

    // Verify ELF32 ARM magic on proxy binary before injecting!
    let proxy_bytes = fs::read(proxy_bin_path)
        .with_context(|| format!("failed to read proxy binary {}", proxy_bin_path.display()))?;
    if proxy_bytes.len() < 20 || &proxy_bytes[0..4] != b"\x7fELF" {
        bail!("proxy binary {} is not an ELF executable", proxy_bin_path.display());
    }
    let elf_class = proxy_bytes[4];
    let elf_machine = u16::from_le_bytes([proxy_bytes[18], proxy_bytes[19]]);
    if elf_class != 1 || elf_machine != 40 {
        bail!(
            "proxy binary {} must be ELF32 ARM (class=1, machine=40), got class={}, machine={}",
            proxy_bin_path.display(),
            elf_class,
            elf_machine
        );
    }

    let mut patched = Vec::new();

    // 1. Install ARM32 static modern-tls-proxy binary in /pfrm2.0/bin/ and symlink in /pfrm2.0/usr/sbin/
    let dst_bin = root.join("bin/modern-tls-proxy");
    fs::write(&dst_bin, &proxy_bytes)?;
    fs::set_permissions(&dst_bin, fs::Permissions::from_mode(0o755))?;
    patched.push("/pfrm2.0/bin/modern-tls-proxy".to_string());

    let usr_sbin = root.join("usr/sbin");
    fs::create_dir_all(&usr_sbin)?;
    let usr_sbin_link = usr_sbin.join("modern-tls-proxy");
    if usr_sbin_link.symlink_metadata().is_ok() {
        let _ = fs::remove_file(&usr_sbin_link);
    }
    symlink("../../bin/modern-tls-proxy", &usr_sbin_link)?;
    patched.push("/pfrm2.0/usr/sbin/modern-tls-proxy -> ../../bin/modern-tls-proxy".to_string());

    // 2. Wrap /pfrm2.0/bin/thttpd -> thttpd.orig (idempotent)
    let thttpd_path = root.join("bin/thttpd");
    let thttpd_orig = root.join("bin/thttpd.orig");
    if !thttpd_orig.exists() {
        if !thttpd_path.exists() {
            bail!("expected /pfrm2.0/bin/thttpd missing in squashfs-root");
        }
        fs::rename(&thttpd_path, &thttpd_orig)?;
        fs::set_permissions(&thttpd_orig, fs::Permissions::from_mode(0o755))?;
        patched.push("/pfrm2.0/bin/thttpd.orig (original ELF preserved)".to_string());
    }
    fs::write(&thttpd_path, THTTPD_WRAPPER)?;
    fs::set_permissions(&thttpd_path, fs::Permissions::from_mode(0o755))?;
    patched.push("/pfrm2.0/bin/thttpd (TLS 1.2/1.3 wrapper)".to_string());

    // 3. Patch /pfrm2.0/bin/thttpdKeepAlive.sh watchdog
    let keepalive = root.join("bin/thttpdKeepAlive.sh");
    fs::write(&keepalive, THTTPD_KEEPALIVE_PATCHED)?;
    fs::set_permissions(&keepalive, fs::Permissions::from_mode(0o755))?;
    patched.push("/pfrm2.0/bin/thttpdKeepAlive.sh".to_string());

    // 4. Patch legacy JS compatibility in /pfrm2.0/var/www/js/
    let bdetect = root.join("var/www/js/bdetect.js");
    if bdetect.exists() {
        fs::write(&bdetect, MODERN_BDETECT_JS)?;
        fs::set_permissions(&bdetect, fs::Permissions::from_mode(0o644))?;
        patched.push("/pfrm2.0/var/www/js/bdetect.js".to_string());
    }
    let ajax_req = root.join("var/www/js/ajaxRequests.js");
    if ajax_req.exists() {
        fs::write(&ajax_req, MODERN_AJAX_REQUESTS_JS)?;
        fs::set_permissions(&ajax_req, fs::Permissions::from_mode(0o644))?;
        patched.push("/pfrm2.0/var/www/js/ajaxRequests.js".to_string());
    }

    // 5. Add new diagnostics page & CGI endpoint (/pfrm2.0/var/www/modStatus.{cgi,htm})
    let status_cgi = root.join("var/www/modStatus.cgi");
    fs::write(&status_cgi, MOD_STATUS_CGI)?;
    fs::set_permissions(&status_cgi, fs::Permissions::from_mode(0o755))?;
    patched.push("/pfrm2.0/var/www/modStatus.cgi".to_string());

    let status_htm = root.join("var/www/modStatus.htm");
    fs::write(&status_htm, MOD_STATUS_HTM)?;
    fs::set_permissions(&status_htm, fs::Permissions::from_mode(0o644))?;
    patched.push("/pfrm2.0/var/www/modStatus.htm".to_string());

    // 6. Write mod release marker in /pfrm2.0/etc/mod_release
    let mod_rel = root.join("etc/mod_release");
    fs::write(
        &mod_rel,
        "MOD_NAME=rv180w-modern-tls\nBASE_FIRMWARE=1.0.5.4\nTLS_VERSIONS=1.2,1.3\n",
    )?;
    fs::set_permissions(&mod_rel, fs::Permissions::from_mode(0o644))?;
    patched.push("/pfrm2.0/etc/mod_release".to_string());

    Ok(PatchReport {
        proxy_size_bytes: proxy_bytes.len() as u64,
        patched_files: patched,
    })
}

const FAST_BOOT_INIT: &str = r#"#!/bin/sh
# rv180w-next v3.0 Fast-Boot Init (replaces 50+ sequential TeamF1 scripts & SQLite rebuild)
# Anti-brick failsafes:
#   1) /data/rv180w/.legacy_boot flag file
#   2) Physical Reset button held at boot (/proc/push_button == 1)
#   3) Automatic fallback to platformInit.legacy if rv180wd --boot fails/crashes

export PATH=/pfrm2.0/bin:/bin:/sbin:/usr/bin:/usr/sbin
export LD_LIBRARY_PATH=/pfrm2.0/lib:/lib:/usr/lib

mkdir -p /data /tmp /var/run /var/log
mountpoint -q /data || mount -t jffs2 -onoatime,nodiratime /dev/mtdblock3 /data 2>/dev/null
mkdir -p /data/rv180w /data/tmp

# Failsafe 1 & 2: legacy flag or Reset button held during boot
RESET_HELD=0
if [ -r /proc/push_button ]; then
    RESET_HELD="$(cat /proc/push_button 2>/dev/null | tr -d '[:space:]')"
fi
if [ -f /data/rv180w/.legacy_boot ] || [ "$RESET_HELD" = "1" ]; then
    echo "[rv180w-next] Failsafe triggered -> exec platformInit.legacy" >/dev/console
    exec /bin/sh /pfrm2.0/etc/platformInit.legacy
fi

echo "[rv180w-next] Fast-booting Cisco RV180W (Pure Rust control plane)..." | tee /tmp/rv180wd-boot.log >/dev/console

KREL="$(uname -r 2>/dev/null)"

# Essential hardware modules (idempotent; rcS loads cns3xxx/sppe/leds before platformInit)
# NOTE: Do NOT run `vlan_table_func init` here — rcS already populated VLAN 1 (LAN) & VLAN 2 (WAN) MAC tables.
for mod in \
    "/pfrm2.0/lib/modules/${KREL}/kernel/drivers/net/cns3xxx/cns3xxx.ko" \
    "/pfrm2.0/lib/modules/cns3xxx.ko" \
    "/pfrm2.0/lib/modules/${KREL}/kernel/drivers/net/cns3xxx/scm-led.ko" \
    "/pfrm2.0/lib/modules/${KREL}/kernel/drivers/net/cns3xxx/push_button.ko" \
    "/pfrm2.0/lib/modules/sppe.ko" \
    "/pfrm2.0/lib/modules/powerMode.ko"; do
    [ -f "$mod" ] && insmod "$mod" >/dev/null 2>&1 || true
done

# 1. Load Broadcom switch driver with exact bcmswitch="bcm5395" param & create /dev/bcm53980
if [ -f /pfrm2.0/lib/modules/swdrv/bcm5398.ko ]; then
    insmod /pfrm2.0/lib/modules/swdrv/bcm5398.ko bcmswitch="bcm5395" >/dev/console 2>&1 || true
    BCM_MAJOR="$(awk '$2=="bcm5395" {print $1}' /proc/devices 2>/dev/null)"
    if [ -n "$BCM_MAJOR" ] && [ ! -e /dev/bcm53980 ]; then
        mknod /dev/bcm53980 c "$BCM_MAJOR" 0 2>/dev/null || true
    fi
fi

# Bring up loopback immediately
/bin/busybox ifconfig lo 127.0.0.1 up >/dev/null 2>&1 || true

# 2. Load Wi-Fi Atheros MADWiFi modules (non-fatal)
MODULES_DIR=/pfrm2.0/lib/modules/dot11
if [ -d "$MODULES_DIR" ]; then
    for mod in kdot11 wlan wlan_scan_ap ath_hal ath_dfs ath_rate_sample; do
        [ -f "$MODULES_DIR/${mod}.ko" ] && insmod "$MODULES_DIR/${mod}.ko" >/dev/null 2>&1 || true
    done
    [ -f "$MODULES_DIR/ath_pci.ko" ] && insmod "$MODULES_DIR/ath_pci.ko" autocreate=none >/dev/null 2>&1 || true
    for mod in wlan_xauth wlan_ccmp wlan_tkip wlan_acl; do
        [ -f "$MODULES_DIR/${mod}.ko" ] && insmod "$MODULES_DIR/${mod}.ko" >/dev/null 2>&1 || true
    done
fi

# 3. Apply persisted atomic config.json (sets bdg1=192.168.1.1 over eth0.1 VLAN 1, dnsmasq, firewall)
# Failsafe 3: if rv180wd crashes/fails hard, automatically revert to stock platformInit.legacy
if ! /pfrm2.0/bin/rv180wd --boot >/dev/console 2>&1; then
    echo "[rv180w-next] rv180wd --boot failed! Reverting to platformInit.legacy" >/dev/console
    exec /bin/sh /pfrm2.0/etc/platformInit.legacy
fi

# 4. Launch single ultra-light control plane daemon (HTTP :80 + HTTPS TLS 1.2/1.3 :443)
if [ -x /pfrm2.0/bin/rv180wd ]; then
    /pfrm2.0/bin/rv180wd --serve >/tmp/rv180wd.log 2>&1 &
    sleep 2
fi

# 5. Print concise live diagnostics directly to UART console
echo "[rv180w-next] LAN interface (bdg1):" >/dev/console
/bin/busybox ifconfig bdg1 >/dev/console 2>&1
echo "[rv180w-next] rv180wd startup log:" >/dev/console
cat /tmp/rv180wd.log >/dev/console 2>&1
echo "[rv180w-next] Ready -> http://192.168.1.1 & https://192.168.1.1" >/dev/console
"#;

/// Patch rootfs for `rv180w-next` v3.0: injects static ARMv6 `rv180wd` and Fast-Boot Init
/// while preserving `/pfrm2.0/etc/platformInit.legacy` for failsafe recovery.
pub fn patch_rootfs_next(work_dir: &Path, rv180wd_bin_path: &Path) -> Result<PatchReport> {
    let root = work_dir.join("squashfs-root");
    if !root.is_dir() {
        bail!(
            "squashfs-root not found at {} — run `unpack` first",
            root.display()
        );
    }
    if !rv180wd_bin_path.is_file() {
        bail!(
            "ARM32 rv180wd binary not found at {}",
            rv180wd_bin_path.display()
        );
    }

    let bin_bytes = fs::read(rv180wd_bin_path)
        .with_context(|| format!("failed to read rv180wd binary {}", rv180wd_bin_path.display()))?;
    if bin_bytes.len() < 20 || &bin_bytes[0..4] != b"\x7fELF" {
        bail!("rv180wd binary {} is not an ELF executable", rv180wd_bin_path.display());
    }
    let elf_class = bin_bytes[4];
    let elf_machine = u16::from_le_bytes([bin_bytes[18], bin_bytes[19]]);
    if elf_class != 1 || elf_machine != 40 {
        bail!(
            "rv180wd binary {} must be ELF32 ARM (class=1, machine=40), got class={}, machine={}",
            rv180wd_bin_path.display(),
            elf_class,
            elf_machine
        );
    }

    let mut patched = Vec::new();

    // 1. Install static ARMv6 rv180wd binary
    let dst_bin = root.join("bin/rv180wd");
    fs::write(&dst_bin, &bin_bytes)?;
    fs::set_permissions(&dst_bin, fs::Permissions::from_mode(0o755))?;
    patched.push("/pfrm2.0/bin/rv180wd (static ARMv6 Rust control plane)".to_string());

    // 2. Preserve stock platformInit as platformInit.legacy and install fastBootInit hook
    let plat_init = root.join("etc/platformInit");
    let plat_legacy = root.join("etc/platformInit.legacy");
    if !plat_legacy.exists() && plat_init.exists() {
        fs::rename(&plat_init, &plat_legacy)?;
        fs::set_permissions(&plat_legacy, fs::Permissions::from_mode(0o755))?;
        patched.push("/pfrm2.0/etc/platformInit.legacy (failsafe preserved)".to_string());
    }
    let fast_init = root.join("etc/fastBootInit");
    fs::write(&fast_init, FAST_BOOT_INIT)?;
    fs::set_permissions(&fast_init, fs::Permissions::from_mode(0o755))?;
    patched.push("/pfrm2.0/etc/fastBootInit".to_string());

    // rcS sources `./platformInit` (`. ./platformInit`), so delegate to fastBootInit safely
    fs::write(&plat_init, "#!/bin/sh\n. /pfrm2.0/etc/fastBootInit\n")?;
    fs::set_permissions(&plat_init, fs::Permissions::from_mode(0o755))?;
    patched.push("/pfrm2.0/etc/platformInit -> fastBootInit".to_string());

    // 3. Replace hardwareNat.lua (invoked by rcS after platformInit) so it doesn't query missing SQLite DB
    let hw_nat = root.join("bin/hardwareNat.lua");
    if hw_nat.exists() {
        fs::write(&hw_nat, "-- Managed by rv180wd (no SQLite dependency)\n")?;
        fs::set_permissions(&hw_nat, fs::Permissions::from_mode(0o755))?;
        patched.push("/pfrm2.0/bin/hardwareNat.lua (clean no-SQLite stub)".to_string());
    }

    // 4. Write v3.0 release marker
    let mod_rel = root.join("etc/mod_release");
    fs::write(
        &mod_rel,
        "MOD_NAME=rv180w-next\nVERSION=3.0.0-beta\nBASE_FIRMWARE=1.0.5.4\nTLS_VERSIONS=1.2,1.3\n",
    )?;
    fs::set_permissions(&mod_rel, fs::Permissions::from_mode(0o644))?;
    patched.push("/pfrm2.0/etc/mod_release".to_string());

    Ok(PatchReport {
        proxy_size_bytes: bin_bytes.len() as u64,
        patched_files: patched,
    })
}
