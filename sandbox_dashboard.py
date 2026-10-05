#!/usr/bin/env python3
r"""
Sandbox Dashboard - before/after snapshot tool for a Windows analysis VM.

Workflow (matches the buttons on the dashboard):
  1. Create a project      -> makes Desktop\<project name>\
  2. Browse for PE / MSI   -> pick the file to test
  3. 1st shot              -> saves the current state to <project>\Before\
  4. Install/Run           -> starts the live recording (Procmon + packet capture), then starts the file
  5. 2nd shot              -> stops the recording, saves the new state to <project>\After\
  6. Compare               -> writes <project>\Compare\ (what was added / removed / changed)
  7. Generate Report       -> writes <project>\<project>_Report.pdf

Needs only Python 3.8+ (standard library). Run it as Administrator inside the VM.
"""
import csv
import ctypes
import hashlib
import io
import ipaddress
import json
import os
import platform
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import zlib
from collections import Counter
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
except ImportError:  # lets the non-GUI parts be imported and tested without Tk
    tk = None

# ====================================================================
# SETTINGS - these are the starting values. Change them from the Settings button on the
# dashboard; your choices are saved in sandbox_settings.json next to this script.
# ====================================================================
SANDBOX_NAME = "Sand Box"                 # title shown on the dashboard and the report
ORG_NAME = ""                             # organisation name printed on the report
ANALYST = ""                              # analyst name printed on the report
LOGO_FILE = ""                            # PNG or JPG logo printed on the report
TOOLS_DIR = r"C:\SandboxTools"            # folder with cports.exe, autorunsc64.exe, Procmon64.exe
CPORTS_EXE = "cports.exe"                 # NirSoft CurrPorts
AUTORUNSC_EXE = "autorunsc64.exe"         # Sysinternals Autoruns command-line (autorunsc.exe also tried)
PROCMON_EXE = "Procmon64.exe"             # Sysinternals Process Monitor (Procmon.exe also tried)
REGISTRY_ROOTS = ["HKLM", "HKU"]          # whole registry, the same two areas Regshot scans
FILE_ROOTS = [                            # folders watched for new / changed / deleted files
    r"C:\Users", r"C:\ProgramData", r"C:\Program Files", r"C:\Program Files (x86)",
    r"C:\Windows\Temp", r"C:\Windows\System32\drivers", r"C:\Windows\System32\Tasks", r"C:\Windows\Tasks",
]
FILE_EXCLUDE = []                         # folders to leave out of the file check (full paths)
LIVE_RECORDING = True                     # record with Procmon + packet capture while the file runs
KEEP_RAW_CAPTURES = False                 # keep the big raw .pml / .etl files after converting them
PKTMON_MAX_MB = 512                       # largest packet capture file
PROCMON_CONVERT_TIMEOUT = 1800            # seconds allowed for Procmon to save its CSV
AUTORUNS_TIMEOUT = 900                    # seconds
HASH_MAX_BYTES = 64 * 1024 * 1024         # new files bigger than this are listed without a SHA-256
MAX_ITEMS = 300                           # most lines listed per category in the report
# ====================================================================

TOOLS = [  # (id, label on dashboard, output file) - taken in both shots
    ("registry", "Regshot (registry)", "registry.txt"),
    ("files", "Files", "files.txt"),
    ("cports", "CC port (CurrPorts)", "cports.csv"),
    ("netstat", "Netstat", "netstat.txt"),
    ("processes", "Process explore", "processes.csv"),
    ("autoruns", "Auto Run", "autoruns.csv"),
    ("services", "Services", "services.csv"),
    ("tasks", "Schedule task", "tasks.csv"),
]
LIVE_ITEMS = [  # recorded between Install/Run and the 2nd shot
    ("procmon", "Procmon (live activity)"),
    ("network", "Network capture"),
]
SECTIONS = [(t[0], t[1]) for t in TOOLS] + [   # sections of the comparison and the report
    ("live", "Live activity while it ran (Procmon)"),
    ("network", "Network activity while it ran"),
]
FULL_LIST = {"registry": "registry_diff.txt", "files": "files_diff.txt", "live": "live_activity.txt",
             "network": "network_activity.txt"}
TOOL_LABEL = {t[0]: t[1] for t in TOOLS}
TOOL_FILE = {t[0]: t[2] for t in TOOLS}
NO_WINDOW = 0x08000000 if os.name == "nt" else 0
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(SCRIPT_DIR, "sandbox_settings.json")
SETTING_KEYS = ["SANDBOX_NAME", "ORG_NAME", "ANALYST", "LOGO_FILE", "TOOLS_DIR", "FILE_ROOTS", "FILE_EXCLUDE",
                "LIVE_RECORDING", "KEEP_RAW_CAPTURES", "MAX_ITEMS"]  # what the Settings window can change
DEFAULTS = {k: globals()[k] for k in SETTING_KEYS}

try:
    csv.field_size_limit(2 ** 31 - 1)
except OverflowError:
    pass


class ToolSkipped(Exception):
    """Raised when a tool is not installed or was not used; the work carries on without it."""


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def is_admin():
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def desktop_dir():
    if os.name == "nt":
        try:
            import winreg
            key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
                p = os.path.expandvars(winreg.QueryValueEx(k, "Desktop")[0])
            if os.path.isdir(p):
                return p
        except OSError:
            pass
    p = os.path.join(os.path.expanduser("~"), "Desktop")
    os.makedirs(p, exist_ok=True)
    return p


def find_tool(*names, tools_dir=None):
    """Look for a tool in the tools folder (and its sub-folders), next to this script, then on PATH."""
    for name in names:
        if os.path.isabs(name) and os.path.isfile(name):
            return name
    for base in (tools_dir or TOOLS_DIR, SCRIPT_DIR, os.path.join(SCRIPT_DIR, "tools")):
        if not os.path.isdir(base):
            continue
        for folder, _dirs, files in os.walk(base):
            lower = {f.lower(): f for f in files}
            for name in names:
                if name.lower() in lower:
                    return os.path.join(folder, lower[name.lower()])
    for name in names:
        hit = shutil.which(name)
        if hit:
            return hit
    return None


def decode_bytes(data):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    if data[:200].count(b"\x00") > 20:
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("oem" if os.name == "nt" else "cp1252", "replace")


def read_text(path):
    with open(path, "rb") as f:
        return decode_bytes(f.read())


def open_text(path):
    """Open a (possibly very large) text file for reading line by line, whatever its encoding."""
    with open(path, "rb") as f:
        head = f.read(4)
    enc = "utf-16" if head[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    return open(path, encoding=enc, errors="replace", newline="")


def write_text(path, text):
    with open(path, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as f:
        f.write(text)


def load_csv(path):
    return list(csv.DictReader(io.StringIO(read_text(path))))


def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def apply_settings(values):
    """Use the given settings from now on. Values of the wrong kind are ignored."""
    for k in SETTING_KEYS:
        if k in values and type(values[k]) is type(DEFAULTS[k]):
            globals()[k] = list(values[k]) if isinstance(values[k], list) else values[k]


def current_settings():
    return {k: globals()[k] for k in SETTING_KEYS}


def load_settings():
    apply_settings(load_json(SETTINGS_FILE, {}) or {})


def save_settings(values):
    apply_settings(values)
    write_text(SETTINGS_FILE, json.dumps(current_settings(), indent=2))


def run_cmd(args, timeout=300):
    return subprocess.run(args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)


def cmd_output(r):
    return decode_bytes((r.stdout or b"") + (r.stderr or b"")).strip()[:300]


def run_powershell(script, out_path, timeout=300):
    quoted = "'" + out_path.replace("'", "''") + "'"
    script = script + " | Export-Csv -NoTypeInformation -Encoding UTF8 -Path " + quoted
    r = run_cmd(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)
    if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
        raise RuntimeError("PowerShell gave no output: " + decode_bytes(r.stderr)[:300])


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def clean(s):
    return str(s).replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")


def new_cats(*names):
    return {n: {"count": 0, "items": []} for n in names}


def merge(ia, ib):
    """Pair up two record streams that are sorted the same way.
    Yields (before, after); one side is None when the record exists on the other side only."""
    a, b = next(ia, None), next(ib, None)
    while a is not None or b is not None:
        if b is None or (a is not None and a[0] < b[0]):
            yield a, None
            a = next(ia, None)
        elif a is None or b[0] < a[0]:
            yield None, b
            b = next(ib, None)
        else:
            yield a, b
            a, b = next(ia, None), next(ib, None)


# --------------------------------------------------------------------
# Registry snapshot (does what Regshot does, but without clicking)
# --------------------------------------------------------------------
HIVES = {"HKLM": "HKEY_LOCAL_MACHINE", "HKU": "HKEY_USERS", "HKCU": "HKEY_CURRENT_USER",
         "HKCR": "HKEY_CLASSES_ROOT", "HKCC": "HKEY_CURRENT_CONFIG"}
REG_TYPES = {0: "NONE", 1: "SZ", 2: "EXPAND_SZ", 3: "BINARY", 4: "DWORD", 7: "MULTI_SZ", 11: "QWORD"}


def path_key(path):
    return tuple(path.lower().split("\\"))


def normalize_roots(roots):
    out = []
    for r in roots:
        parts = [p for p in r.strip().split("\\") if p]
        if not parts:
            continue
        hive = parts[0].upper()
        hive = {v: k for k, v in HIVES.items()}.get(hive, hive)
        if hive not in HIVES:
            raise ValueError("Unknown registry root: " + r)
        out.append((hive, "\\".join(parts[1:])))
    full = lambda r: r[0] + ("\\" + r[1] if r[1] else "")
    out.sort(key=lambda r: path_key(full(r)))
    kept, keys = [], []
    for r in out:  # drop roots that sit inside another root
        k = path_key(full(r))
        if any(k[:len(pk)] == pk for pk in keys):
            continue
        kept.append(r)
        keys.append(k)
    return kept


def fmt_reg_data(data):
    if data is None:
        s = ""
    elif isinstance(data, bytes):
        s = data.hex()
    elif isinstance(data, list):
        s = " | ".join(str(x) for x in data)
    else:
        s = str(data)
    if len(s) > 200:
        digest = hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:16]
        s = "%s ...[len=%d sha1=%s]" % (s[:120], len(s), digest)
    return clean(s)


def snapshot_registry(out_path, roots=None, api=None, progress=None):
    """Write every key and value under the roots, in a fixed order, one per line."""
    if api is None:
        import winreg as api
    access = api.KEY_READ | getattr(api, "KEY_WOW64_64KEY", 0)
    nkeys = nvals = 0
    with open(out_path, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as f:
        for hive, sub in normalize_roots(roots or REGISTRY_ROOTS):
            hroot = getattr(api, HIVES[hive])
            stack = [sub]
            while stack:
                rel = stack.pop()
                f.write("K\t%s\n" % clean(hive + ("\\" + rel if rel else "")))
                nkeys += 1
                if progress and nkeys % 100000 == 0:
                    progress("  registry: %d keys read..." % nkeys)
                try:
                    h = api.OpenKey(hroot, rel, 0, access)
                except OSError:
                    continue  # no permission (e.g. SAM) or key vanished
                try:
                    try:
                        nsub, nval, _ = api.QueryInfoKey(h)
                    except OSError:
                        nsub = nval = 0
                    vals = []
                    for i in range(nval):
                        try:
                            vals.append(api.EnumValue(h, i))
                        except OSError:
                            break
                    full = clean(hive + ("\\" + rel if rel else ""))
                    for name, data, typ in sorted(vals, key=lambda v: v[0].lower()):
                        f.write("V\t%s\t%s\t%s\t%s\n" % (full, clean(name), REG_TYPES.get(typ, str(typ)),
                                                        fmt_reg_data(data)))
                        nvals += 1
                    subs = []
                    for i in range(nsub):
                        try:
                            subs.append(api.EnumKey(h, i))
                        except OSError:
                            break
                    for s in sorted(subs, key=str.lower, reverse=True):
                        stack.append(rel + "\\" + s if rel else s)
                finally:
                    api.CloseKey(h)
    return "%d keys, %d values" % (nkeys, nvals)


def _reg_records(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if p[0] == "K" and len(p) >= 2:
                yield (path_key(p[1]), 0, ""), p
            elif p[0] == "V" and len(p) >= 5:
                yield (path_key(p[1]), 1, p[2].lower()), p


def diff_registry(before, after, out_path, cap=None):
    """Walk both snapshots side by side (they are in the same order), so memory use stays small."""
    cap = MAX_ITEMS if cap is None else cap
    cats = new_cats("keys added", "keys deleted", "values added", "values deleted", "values modified")

    def val(p):
        return "%s\\[%s] = (%s) %s" % (p[1], p[2] or "(Default)", p[3], p[4])

    with open(out_path, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as out:
        def hit(cat, mark, text):
            c = cats[cat]
            c["count"] += 1
            if len(c["items"]) < cap:
                c["items"].append(text)
            out.write("%s %s\n" % (mark, text))

        for a, b in merge(_reg_records(before), _reg_records(after)):
            if b is None:
                p = a[1]
                hit("keys deleted", "-K", p[1]) if p[0] == "K" else hit("values deleted", "-V", val(p))
            elif a is None:
                p = b[1]
                hit("keys added", "+K", p[1]) if p[0] == "K" else hit("values added", "+V", val(p))
            else:
                pa, pb = a[1], b[1]
                if pa[0] == "V" and pa[3:5] != pb[3:5]:
                    hit("values modified", "~V", "%s\\[%s]: (%s) %s  ->  (%s) %s"
                        % (pa[1], pa[2] or "(Default)", pa[3], pa[4], pb[3], pb[4]))
    return cats


# --------------------------------------------------------------------
# File snapshot (new / changed / deleted files and folders)
# --------------------------------------------------------------------
def file_key(path):
    return tuple(path.lower().replace("/", "\\").split("\\"))


def snapshot_files(out_path, roots=None, exclude=(), progress=None):
    """Write every file (with size and modified time) and folder under the roots, in a fixed order."""
    skip = [file_key(os.path.abspath(e)) for e in exclude if e]
    todo = sorted({os.path.abspath(os.path.expandvars(r)) for r in (roots or FILE_ROOTS)}, key=file_key)
    kept = []
    for r in todo:  # only folders that exist, and not ones inside another root
        k = file_key(r)
        if os.path.isdir(r) and not any(k[:len(file_key(p))] == file_key(p) for p in kept):
            kept.append(r)
    prefix = "\\\\?\\" if os.name == "nt" else ""  # lets Windows open paths longer than 260 characters
    nfiles = ndirs = 0
    with open(out_path, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as f:
        for root in kept:
            stack = [(root, True, 0, 0)]
            while stack:
                path, is_dir, size, mtime = stack.pop()
                if not is_dir:
                    f.write("F\t%s\t%d\t%d\n" % (clean(path), size, mtime))
                    nfiles += 1
                    continue
                f.write("D\t%s\n" % clean(path))
                ndirs += 1
                if progress and ndirs % 20000 == 0:
                    progress("  files: %d folders, %d files read..." % (ndirs, nfiles))
                kids = []
                try:
                    with os.scandir(prefix + path) as entries:
                        for e in entries:
                            full = os.path.join(path, e.name)
                            k = file_key(full)
                            if any(k[:len(x)] == x for x in skip):
                                continue
                            try:
                                st = e.stat(follow_symlinks=False)
                                # links and junctions are listed but not followed (they can loop)
                                link = e.is_symlink() or bool(getattr(st, "st_file_attributes", 0) & 0x400)
                                if not link and e.is_dir(follow_symlinks=False):
                                    kids.append((e.name.lower(), full, True, 0, 0))
                                else:
                                    kids.append((e.name.lower(), full, False, st.st_size, int(st.st_mtime)))
                            except OSError:
                                continue
                except OSError:
                    continue  # no permission, or the folder vanished
                kids.sort(reverse=True)
                stack.extend(k[1:] for k in kids)
    return "%d files, %d folders" % (nfiles, ndirs)


def _file_records(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if (p[0] == "D" and len(p) >= 2) or (p[0] == "F" and len(p) >= 4):
                yield file_key(p[1]), p


def _try_hash(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) <= HASH_MAX_BYTES:
            return " | sha256=" + sha256_file(path)
    except OSError:
        pass
    return ""


def diff_files(before, after, out_path, cap=None):
    cap = MAX_ITEMS if cap is None else cap
    cats = new_cats("files added", "files deleted", "files modified", "folders added", "folders deleted")
    with open(out_path, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as out:
        def hit(cat, mark, text, hash_path=None):
            c = cats[cat]
            c["count"] += 1
            if len(c["items"]) < cap:
                if hash_path:  # fingerprint of the file as it is now (only for the ones listed in the report)
                    text += _try_hash(hash_path)
                c["items"].append(text)
            out.write("%s %s\n" % (mark, text))

        def gone(p):
            if p[0] == "F":
                hit("files deleted", "-F", "%s | %s bytes" % (p[1], p[2]))
            else:
                hit("folders deleted", "-D", p[1])

        def new(p):
            if p[0] == "F":
                hit("files added", "+F", "%s | %s bytes" % (p[1], p[2]), p[1])
            else:
                hit("folders added", "+D", p[1])

        for a, b in merge(_file_records(before), _file_records(after)):
            if a is not None and b is not None and a[1][0] == b[1][0]:
                pa, pb = a[1], b[1]
                if pa[0] == "F" and pa[2:4] != pb[2:4]:
                    hit("files modified", "~F", "%s | %s -> %s bytes" % (pb[1], pa[2], pb[2]), pb[1])
                continue
            if a is not None:
                gone(a[1])
            if b is not None:
                new(b[1])
    return cats


# --------------------------------------------------------------------
# Snapshot collectors (one per tool)
# --------------------------------------------------------------------
def collect_registry(out, log):
    return snapshot_registry(out, progress=log)


def collect_files(out, log):
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(out)))
    return snapshot_files(out, exclude=list(FILE_EXCLUDE) + [project_dir], progress=log)


def collect_cports(out, log):
    exe = find_tool(CPORTS_EXE, "cports.exe")
    if not exe:
        raise ToolSkipped("cports.exe not found in %s" % TOOLS_DIR)
    run_cmd([exe, "/scomma", out], 120)
    if not os.path.isfile(out):
        raise RuntimeError("CurrPorts wrote no file")
    return os.path.basename(exe)


def collect_netstat(out, log):
    r = run_cmd(["netstat", "-ano"], 120)
    text = decode_bytes(r.stdout)
    if "TCP" not in text and "UDP" not in text:
        raise RuntimeError("netstat gave no output: " + decode_bytes(r.stderr)[:200])
    write_text(out, text)
    return "%d lines" % len(text.splitlines())


def collect_processes(out, log):
    run_powershell("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,"
                   "ExecutablePath,CommandLine", out)
    return "%d processes" % len(load_csv(out))


def collect_autoruns(out, log):
    exe = find_tool(AUTORUNSC_EXE, "autorunsc64.exe", "autorunsc.exe")
    if not exe:
        raise ToolSkipped("autorunsc.exe not found in %s" % TOOLS_DIR)
    log("  autoruns: scanning, this can take a few minutes...")
    r = run_cmd([exe, "-accepteula", "-nobanner", "-a", "*", "-c", "*"], AUTORUNS_TIMEOUT)
    text = decode_bytes(r.stdout)
    if "Entry" not in text:
        raise RuntimeError("autorunsc gave no output: " + decode_bytes(r.stderr)[:200])
    write_text(out, text)
    return "%d lines" % len(text.splitlines())


def collect_services(out, log):
    run_powershell("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,"
                   "StartName,PathName", out)
    return "%d services" % len(load_csv(out))


def collect_tasks(out, log):
    run_powershell("Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Author,@{n='Actions';e={"
                   "($_.Actions | ForEach-Object { if ($_.Execute) { ($_.Execute + ' ' + $_.Arguments).Trim() }"
                   " else { 'COM ' + $_.ClassId } }) -join ' ; '}}", out)
    return "%d tasks" % len(load_csv(out))


COLLECTORS = {"registry": collect_registry, "files": collect_files, "cports": collect_cports,
              "netstat": collect_netstat, "processes": collect_processes, "autoruns": collect_autoruns,
              "services": collect_services, "tasks": collect_tasks}


def take_snapshot(project_dir, phase, log, on_status):
    """phase is 'Before' or 'After'. Runs every tool and saves its output in that folder."""
    folder = os.path.join(project_dir, phase)
    os.makedirs(folder, exist_ok=True)
    info = {"phase": phase, "started": now(), "tools": {}}
    for tid, label, fname in TOOLS:
        on_status(tid, "running")
        out = os.path.join(folder, fname)
        if os.path.exists(out):
            os.remove(out)
        try:
            note = COLLECTORS[tid](out, log)
            state = "done"
        except ToolSkipped as e:
            state, note = "skipped", str(e)
        except Exception as e:
            state, note = "failed", "%s: %s" % (type(e).__name__, e)
        info["tools"][tid] = {"state": state, "note": note}
        log("  %-24s %s - %s" % (label, state.upper(), note))
        on_status(tid, state)
    info["finished"] = now()
    write_text(os.path.join(folder, "snapshot_info.json"), json.dumps(info, indent=2))
    return info


# --------------------------------------------------------------------
# Live recording between Install/Run and the 2nd shot
#   Procmon  -> Live\procmon.csv     (every process, file, registry and network event)
#   pktmon   -> Live\network.pcapng  (packets; opens in Wireshark)
#   DNS      -> Live\dns_cache.csv   (domain names Windows looked up)
# --------------------------------------------------------------------
def live_path(project_dir, name=""):
    return os.path.join(project_dir, "Live", name)


def load_live(project_dir):
    return load_json(live_path(project_dir, "live_info.json"), {})


def live_state(info, key):
    return (info.get(key) or {}).get("state", "pending")


def needs_stop(info):
    return info.get("dns") == "pending" or any(live_state(info, k) == "recording" for k, _ in LIVE_ITEMS)


def _live_setter(project_dir, info, log, mark):
    labels = dict(LIVE_ITEMS)

    def setstate(key, state, note=""):
        info[key] = dict(info.get(key) or {}, state=state, note=note)
        write_text(live_path(project_dir, "live_info.json"), json.dumps(info, indent=2))
        mark(key, state)
        log("  %-24s %s%s" % (labels[key], state.upper(), " - " + note if note else ""))
    return setstate


def start_recording(project_dir, log, mark):
    """Start Procmon and the packet capture. Anything that cannot start is skipped; the run goes on."""
    shutil.rmtree(live_path(project_dir), ignore_errors=True)
    os.makedirs(live_path(project_dir), exist_ok=True)
    info = {"started": now(), "dns": "pending"}
    setstate = _live_setter(project_dir, info, log, mark)
    try:
        run_cmd(["ipconfig", "/flushdns"], 30)  # so the DNS cache afterwards holds only names from this run
    except Exception:
        pass

    try:
        run_cmd(["pktmon", "stop"], 60)  # clear any capture left over from an earlier run
        r = run_cmd(["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "0",
                     "--file-size", str(PKTMON_MAX_MB), "--file-name", live_path(project_dir, "network.etl")], 60)
        if r.returncode:
            raise RuntimeError(cmd_output(r))
        setstate("network", "recording")
    except FileNotFoundError:
        setstate("network", "skipped", "pktmon is not available on this Windows version")
    except Exception as e:
        setstate("network", "failed", "%s: %s" % (type(e).__name__, e))

    exe = find_tool(PROCMON_EXE, "Procmon64.exe", "Procmon.exe")
    if not exe:
        setstate("procmon", "skipped", "Procmon64.exe not found in %s" % TOOLS_DIR)
    else:
        try:
            info["procmon"] = {"exe": exe}
            subprocess.Popen([exe, "/AcceptEula", "/Quiet", "/Minimized", "/BackingFile",
                              live_path(project_dir, "procmon.pml")])
            run_cmd([exe, "/AcceptEula", "/WaitForIdle"], 120)  # returns once Procmon is capturing
            setstate("procmon", "recording")
        except Exception as e:
            try:  # do not leave a half-started Procmon recording in the background
                run_cmd([exe, "/AcceptEula", "/Terminate"], 120)
            except Exception:
                pass
            setstate("procmon", "failed", "%s: %s" % (type(e).__name__, e))
    return info


def stop_recording(project_dir, log, mark):
    """Stop the captures (quick). The slow conversions are done by finish_recording."""
    info = load_live(project_dir)
    setstate = _live_setter(project_dir, info, log, mark)
    if live_state(info, "procmon") == "recording":
        try:
            run_cmd([info["procmon"]["exe"], "/AcceptEula", "/Terminate"], 300)
            setstate("procmon", "stopped")
        except Exception as e:
            setstate("procmon", "failed", "could not stop Procmon - %s: %s" % (type(e).__name__, e))
    if live_state(info, "network") == "recording":
        try:
            run_cmd(["pktmon", "stop"], 300)
            setstate("network", "stopped")
        except Exception as e:
            setstate("network", "failed", "could not stop pktmon - %s: %s" % (type(e).__name__, e))
    if info.get("dns") == "pending":
        try:
            run_powershell("Get-DnsClientCache | Select-Object Entry,Name,Type,Status,Data",
                           live_path(project_dir, "dns_cache.csv"), 120)
            info["dns"] = "done"
        except Exception:
            info["dns"] = "empty"  # nothing was looked up, or the cmdlet is missing
    info["stopped"] = now()
    write_text(live_path(project_dir, "live_info.json"), json.dumps(info, indent=2))
    return info


def finish_recording(project_dir, log, mark):
    """Turn the raw captures into files that can be read: procmon.csv and network.pcapng."""
    info = load_live(project_dir)
    setstate = _live_setter(project_dir, info, log, mark)
    if live_state(info, "procmon") == "stopped":
        pml, out = live_path(project_dir, "procmon.pml"), live_path(project_dir, "procmon.csv")
        try:
            log("  procmon: saving the recording as CSV, this can take a few minutes...")
            run_cmd([info["procmon"]["exe"], "/AcceptEula", "/Quiet", "/Minimized", "/OpenLog", pml,
                     "/SaveAs", out], PROCMON_CONVERT_TIMEOUT)
            if not os.path.isfile(out) or os.path.getsize(out) == 0:
                raise RuntimeError("Procmon did not write the CSV file")
            if not KEEP_RAW_CAPTURES and os.path.isfile(pml):
                os.remove(pml)
            setstate("procmon", "done", "%.1f MB" % (os.path.getsize(out) / 1e6))
        except Exception as e:
            setstate("procmon", "failed", "%s: %s" % (type(e).__name__, e))
    if live_state(info, "network") == "stopped":
        etl, out = live_path(project_dir, "network.etl"), live_path(project_dir, "network.pcapng")
        try:
            r = run_cmd(["pktmon", "etl2pcap", etl, "--out", out], 900)
            if not os.path.isfile(out):  # older Windows 10 builds use a different command name
                r = run_cmd(["pktmon", "pcapng", etl, "-o", out], 900)
            if not os.path.isfile(out):
                raise RuntimeError("pktmon did not write the capture: " + cmd_output(r))
            if not KEEP_RAW_CAPTURES and os.path.isfile(etl):
                os.remove(etl)
            setstate("network", "done", "%.1f MB" % (os.path.getsize(out) / 1e6))
        except Exception as e:
            setstate("network", "failed", "%s: %s" % (type(e).__name__, e))
    return info


# ---- reading the Procmon recording ------------------------------------
LIVE_CATS = ["processes started", "files written", "files deleted", "registry values set",
             "registry entries deleted", "network connections by new processes",
             "network connections by other processes"]
PROCMON_OPS = {"Process Start", "Process Create", "WriteFile", "CreateFile", "SetRenameInformationFile",
               "SetDispositionInformationFile", "SetDispositionInformationEx", "RegSetValue", "RegDeleteValue",
               "RegDeleteKey", "TCP Connect", "TCP Accept", "UDP Send"}


def _finish_cats(seen, out_path, cap, title):
    """seen = {category: {key: text}} in first-seen order -> report categories + a full text file."""
    cap = MAX_ITEMS if cap is None else cap
    cats, lines = {}, [title, ""]
    for cat, found in seen.items():
        items = list(found.values())
        cats[cat] = {"count": len(items), "items": items[:cap]}
        lines += ["%s (%d)" % (cat, len(items))] + ["  " + i for i in items] + [""]
    write_text(out_path, "\n".join(lines))
    return cats


def analyze_procmon(csv_path, out_path, cap=None):
    """Summarise a Procmon CSV. File and registry activity is kept only for processes that STARTED
    during the recording (the tested file and everything it launched, plus anything else that started);
    network activity is kept for every process."""
    if not os.path.isfile(csv_path):
        raise ToolSkipped("not recorded")
    seen = {c: {} for c in LIVE_CATS}
    names, images, tracked = {}, {}, set()
    with open_text(csv_path) as f:
        rows = csv.reader(f)
        head = next(rows, [])
        try:
            cols = [head.index(c) for c in ("Process Name", "PID", "Operation", "Path", "Result", "Detail")]
        except ValueError:
            raise RuntimeError("the Procmon CSV has no Process Name / PID / Operation / Path / Result / Detail "
                               "columns - reset Procmon's columns to the defaults")
        need = max(cols)
        ci_op = cols[2]
        for row in rows:
            if len(row) <= need or row[ci_op] not in PROCMON_OPS:
                continue
            proc, pid, op, path, result, detail = (row[i] for i in cols)
            names[pid] = proc
            if op == "Process Create":  # written by the parent; Path is the new program
                m = re.match(r"PID: (\d+)", detail)
                if m:
                    tracked.add(m.group(1))
                    images[m.group(1)] = path
            elif op == "Process Start":  # written by the new process itself
                tracked.add(pid)
                m = re.match(r"Parent PID: (\d+), Command line: (.*?)(?:, Current directory: .*)?$", detail, re.S)
                ppid, cmd = (m.group(1), m.group(2)) if m else ("?", "")
                seen["processes started"][pid] = " | ".join(x for x in (
                    proc, images.get(pid, ""), "PID %s" % pid,
                    "started by %s (PID %s)" % (names.get(ppid, "?"), ppid), clean(cmd)[:400]) if x)
            elif op in ("TCP Connect", "TCP Accept", "UDP Send"):
                remote = path.split(" -> ")[-1]
                cat = "network connections by %s processes" % ("new" if pid in tracked else "other")
                seen[cat].setdefault((proc, op, remote), "%s | %s | %s" % (proc, op, remote))
            elif pid in tracked and result == "SUCCESS":
                if op == "WriteFile" or (op == "CreateFile" and "OpenResult: Created" in detail):
                    seen["files written"].setdefault((proc, path), "%s -> %s" % (proc, path))
                elif op == "SetRenameInformationFile":
                    m = re.search(r"FileName: (.*)$", detail)
                    if m:
                        seen["files written"].setdefault((proc, m.group(1)), "%s -> %s (renamed from %s)"
                                                         % (proc, m.group(1), path))
                elif op.startswith("SetDispositionInformation"):
                    if "Delete: True" in detail or "FILE_DISPOSITION_DELETE" in detail:
                        seen["files deleted"].setdefault((proc, path), "%s -> %s" % (proc, path))
                elif op == "RegSetValue":
                    m = re.search(r"Data: (.*)$", detail, re.S)
                    data = clean(m.group(1))[:200] if m else ""
                    seen["registry values set"][(proc, path)] = "%s -> %s = %s" % (proc, path, data)
                elif op in ("RegDeleteValue", "RegDeleteKey"):
                    seen["registry entries deleted"].setdefault((proc, path), "%s -> %s" % (proc, path))
    return _finish_cats(seen, out_path, cap, "Live activity recorded by Procmon while the file ran")


# ---- reading the packet capture ---------------------------------------
NET_CATS = ["domain names looked up (Windows DNS cache)", "DNS queries seen in packets",
            "host names seen in web traffic", "TCP connections started", "UDP destinations"]
HTTP_VERBS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"PATCH")


def read_pcapng(path):
    """Yield (link type, packet bytes) for every packet in a .pcapng file."""
    with open(path, "rb") as f:
        endian, links = "<", []
        while True:
            head = f.read(8)
            if len(head) < 8:
                return
            if head[:4] == b"\x0a\x0d\x0d\x0a":  # section header: tells us the byte order
                endian = "<" if f.read(4) == b"\x4d\x3c\x2b\x1a" else ">"
                f.read(struct.unpack(endian + "I", head[4:])[0] - 12)
                links = []
                continue
            btype, blen = struct.unpack(endian + "II", head)
            if blen < 12:
                return
            body = f.read(blen - 12)
            f.read(4)
            if btype == 1 and len(body) >= 2:  # interface description
                links.append(struct.unpack(endian + "H", body[:2])[0])
            elif btype == 6 and len(body) >= 20:  # enhanced packet
                iface, _hi, _lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
                yield (links[iface] if iface < len(links) else 1), body[20:20 + caplen]
            elif btype == 3 and len(body) >= 4:  # simple packet
                yield (links[0] if links else 1), body[4:]


def parse_packet(link, d):
    """Return (proto, src, sport, dst, dport, tcp flags, payload) for TCP/UDP packets, else None."""
    try:
        if link == 1:  # Ethernet
            etype, off = int.from_bytes(d[12:14], "big"), 14
            while etype == 0x8100:  # VLAN tag
                etype, off = int.from_bytes(d[off + 2:off + 4], "big"), off + 4
            d = d[off:]
        elif link in (101, 228, 229):  # raw IP
            etype = 0x0800 if d[0] >> 4 == 4 else 0x86DD
        else:
            return None
        if etype == 0x0800:
            if int.from_bytes(d[6:8], "big") & 0x1FFF:
                return None  # later fragment: no TCP/UDP header
            proto, src, dst, d = d[9], d[12:16], d[16:20], d[(d[0] & 15) * 4:]
        elif etype == 0x86DD:
            proto, src, dst, d = d[6], d[8:24], d[24:40], d[40:]
        else:
            return None
        if proto not in (6, 17) or len(d) < 8:
            return None
        sport, dport = int.from_bytes(d[0:2], "big"), int.from_bytes(d[2:4], "big")
        src, dst = ipaddress.ip_address(bytes(src)), ipaddress.ip_address(bytes(dst))
        if proto == 6:
            return proto, src, sport, dst, dport, d[13], d[(d[12] >> 4) * 4:]
        return proto, src, sport, dst, dport, 0, d[8:]
    except (IndexError, ValueError):
        return None


def dns_query_name(d):
    try:
        if len(d) < 17 or d[2] & 0x80 or int.from_bytes(d[4:6], "big") == 0:
            return None  # too short, a reply, or no question
        labels, p = [], 12
        while d[p]:
            if d[p] > 63:
                return None
            labels.append(d[p + 1:p + 1 + d[p]].decode("ascii", "replace"))
            p += 1 + d[p]
        return ".".join(labels) or None
    except IndexError:
        return None


def tls_server_name(d):
    """Server name from a TLS ClientHello (when it fits in the first packet)."""
    try:
        if len(d) < 44 or d[0] != 0x16 or d[5] != 1:
            return None
        p = 43                                             # record header, handshake header, version, random
        p += 1 + d[p]                                      # session id
        p += 2 + int.from_bytes(d[p:p + 2], "big")         # cipher suites
        p += 1 + d[p]                                      # compression methods
        end = p + 2 + int.from_bytes(d[p:p + 2], "big")
        p += 2
        while p + 4 <= min(end, len(d)):
            etype, elen = int.from_bytes(d[p:p + 2], "big"), int.from_bytes(d[p + 2:p + 4], "big")
            p += 4
            if etype == 0:
                n = int.from_bytes(d[p + 3:p + 5], "big")
                name = d[p + 5:p + 5 + n]
                return name.decode("ascii", "replace") if len(name) == n and n else None
            p += elen
    except IndexError:
        pass
    return None


def http_host(d):
    if d[:8].split(b" ")[0] in HTTP_VERBS:
        m = re.search(rb"\r\nHost: *([^\r\n]+)", d[:4000], re.I)
        if m:
            return m.group(1).decode("ascii", "replace").strip()
    return None


def endpoint(ip, port):
    return ("[%s]:%d" if ip.version == 6 else "%s:%d") % (ip, port)


def analyze_network(live_dir, out_path, cap=None):
    dns_csv, pcap = os.path.join(live_dir, "dns_cache.csv"), os.path.join(live_dir, "network.pcapng")
    if not os.path.isfile(dns_csv) and not os.path.isfile(pcap):
        raise ToolSkipped("not recorded")
    seen = {c: {} for c in NET_CATS}
    if os.path.isfile(dns_csv):
        for r in load_csv(dns_csv):
            entry, data = (r.get("Entry") or r.get("Name") or "").strip(), (r.get("Data") or "").strip()
            if entry:
                text = "%s -> %s" % (entry, data) if data else "%s (no answer)" % entry
                seen[NET_CATS[0]].setdefault(text, text)
    if os.path.isfile(pcap):
        for link, raw in read_pcapng(pcap):
            pkt = parse_packet(link, raw)
            if not pkt:
                continue
            proto, src, sport, dst, dport, flags, data = pkt
            if proto == 17:
                if dport == 53:
                    name = dns_query_name(data)
                    if name:
                        text = "%s (asked %s)" % (name, dst)
                        seen[NET_CATS[1]].setdefault(text, text)
                elif dport < 49152 and sport != 53 and not dst.is_multicast and str(dst) != "255.255.255.255":
                    text = "%s -> %s" % (src, endpoint(dst, dport))  # replies go to high ports, so they are left out
                    seen[NET_CATS[4]].setdefault(text, text)
            else:
                if flags & 0x12 == 0x02:  # SYN without ACK = the side that opens the connection
                    text = "%s -> %s" % (src, endpoint(dst, dport))
                    seen[NET_CATS[3]].setdefault(text, text)
                elif data:
                    host = tls_server_name(data) or http_host(data)
                    if host:
                        text = "%s (%s)" % (host, endpoint(dst, dport))
                        seen[NET_CATS[2]].setdefault(text, text)
    return _finish_cats(seen, out_path, cap, "Network activity recorded while the file ran")


# --------------------------------------------------------------------
# Compare
# --------------------------------------------------------------------
def set_diff(before, after, added_name, removed_name):
    cb, ca = Counter(before), Counter(after)
    cats = new_cats(added_name, removed_name)
    for name, diff in ((added_name, ca - cb), (removed_name, cb - ca)):
        items = sorted(k if n == 1 else "%s  (x%d)" % (k, n) for k, n in diff.items())
        cats[name] = {"count": len(items), "items": items}
    return cats


def keyed_diff(before, after, fields, noun):
    cats = new_cats(noun + " added", noun + " removed", noun + " changed")

    def show(row):
        return " | ".join("%s=%s" % (f, row.get(f, "")) for f in fields)

    for k in sorted(set(after) - set(before)):
        cats[noun + " added"]["items"].append("%s | %s" % (k, show(after[k])))
    for k in sorted(set(before) - set(after)):
        cats[noun + " removed"]["items"].append("%s | %s" % (k, show(before[k])))
    for k in sorted(set(before) & set(after)):
        ch = ["%s: %s -> %s" % (f, before[k].get(f, ""), after[k].get(f, ""))
              for f in fields if before[k].get(f, "") != after[k].get(f, "")]
        if ch:
            cats[noun + " changed"]["items"].append("%s | %s" % (k, " ; ".join(ch)))
    for c in cats.values():
        c["count"] = len(c["items"])
    return cats


def _pid_names(folder):
    path = os.path.join(folder, TOOL_FILE["processes"])
    if not os.path.isfile(path):
        return {}
    return {r.get("ProcessId", ""): r.get("Name", "") for r in load_csv(path)}


def parse_netstat(folder):
    names, items = _pid_names(folder), []
    for line in read_text(os.path.join(folder, TOOL_FILE["netstat"])).splitlines():
        p = line.split()
        if len(p) >= 4 and p[0] in ("TCP", "UDP"):
            state = p[3] if p[0] == "TCP" and len(p) >= 5 else ""
            proc = names.get(p[-1]) or "PID " + p[-1]
            items.append(" ".join(x for x in (p[0], p[1], "->", p[2], state, "[%s]" % proc) if x))
    return sorted(set(items))


CPORTS_COLS = ["Process Name", "Protocol", "Local Port", "Local Address", "Remote Port", "Remote Address",
               "State", "Process Path"]
CPORTS_POS = [0, 2, 3, 5, 6, 8, 10, 11]  # same columns by position, used when the CSV has no header row


def parse_cports(folder):
    rows = list(csv.reader(io.StringIO(read_text(os.path.join(folder, TOOL_FILE["cports"])))))
    rows = [r for r in rows if r]
    if not rows:
        return []
    if "Process Name" in rows[0]:
        head = rows[0]
        idx = [head.index(c) for c in CPORTS_COLS if c in head]
        rows = rows[1:]
    else:
        idx = CPORTS_POS
    return sorted({" | ".join(r[i].strip() for i in idx if i < len(r)) for r in rows})


def parse_processes(folder):
    items = []
    for r in load_csv(os.path.join(folder, TOOL_FILE["processes"])):
        cmd = r.get("CommandLine", "") or ""
        if "Win32_Process" in cmd:  # the snapshot's own PowerShell
            continue
        items.append(" | ".join(x for x in (r.get("Name", ""), r.get("ExecutablePath", ""), cmd[:300]) if x))
    return items


def parse_autoruns(folder):
    items = []
    for r in load_csv(os.path.join(folder, TOOL_FILE["autoruns"])):
        if not (r.get("Entry") or "").strip():
            continue
        items.append(" | ".join((r.get(c) or "").strip() for c in
                                ("Category", "Entry Location", "Entry", "Enabled", "Image Path", "Launch String")))
    return sorted(set(items))


def parse_services(folder):
    return {r.get("Name", ""): r for r in load_csv(os.path.join(folder, TOOL_FILE["services"]))}


def parse_tasks(folder):
    out = {}
    for r in load_csv(os.path.join(folder, TOOL_FILE["tasks"])):
        if r.get("State") == "Running":
            r["State"] = "Ready"  # a task that happens to be running is not a change
        out[(r.get("TaskPath", "") or "") + (r.get("TaskName", "") or "")] = r
    return out


def _compare_tool(tid, before, after, fb, fa, cdir):
    if tid == "registry":
        return diff_registry(fb, fa, os.path.join(cdir, FULL_LIST["registry"]))
    if tid == "files":
        return diff_files(fb, fa, os.path.join(cdir, FULL_LIST["files"]))
    if tid == "cports":
        return set_diff(parse_cports(before), parse_cports(after), "ports added", "ports removed")
    if tid == "netstat":
        return set_diff(parse_netstat(before), parse_netstat(after), "connections added", "connections removed")
    if tid == "processes":
        return set_diff(parse_processes(before), parse_processes(after), "processes added", "processes ended")
    if tid == "autoruns":
        return set_diff(parse_autoruns(before), parse_autoruns(after),
                        "autorun entries added", "autorun entries removed")
    if tid == "services":
        return keyed_diff(parse_services(before), parse_services(after),
                          ["State", "StartMode", "StartName", "PathName"], "services")
    return keyed_diff(parse_tasks(before), parse_tasks(after), ["State", "Actions"], "tasks")


def run_compare(project_dir, log=lambda s: None):
    before, after = os.path.join(project_dir, "Before"), os.path.join(project_dir, "After")
    cdir, live = os.path.join(project_dir, "Compare"), live_path(project_dir)
    os.makedirs(cdir, exist_ok=True)
    jobs = []
    for tid, label, fname in TOOLS:
        fb, fa = os.path.join(before, fname), os.path.join(after, fname)
        if os.path.isfile(fb) and os.path.isfile(fa):
            jobs.append((tid, lambda t=tid, b=fb, a=fa: _compare_tool(t, before, after, b, a, cdir)))
        else:
            jobs.append((tid, None))
    jobs.append(("live", lambda: analyze_procmon(os.path.join(live, "procmon.csv"),
                                                 os.path.join(cdir, FULL_LIST["live"]))))
    jobs.append(("network", lambda: analyze_network(live, os.path.join(cdir, FULL_LIST["network"]))))

    results, labels = {}, {sid: label.split(" while")[0] for sid, label in SECTIONS}
    for sid, job in jobs:
        res = {"error": "", "skipped": False, "cats": {}}
        try:
            if job is None:
                raise ToolSkipped("not captured in both shots")
            res["cats"] = job()
            log("  %-24s %s" % (labels[sid], ", ".join("%d %s" % (c["count"], n)
                                                            for n, c in res["cats"].items() if c["count"])
                                or "no changes"))
        except ToolSkipped as e:
            res["error"], res["skipped"] = str(e), True
            log("  %-24s skipped (%s)" % (labels[sid], e))
        except Exception as e:
            res["error"] = "%s: %s" % (type(e).__name__, e)
            log("  %-24s FAILED - %s" % (labels[sid], res["error"]))
        results[sid] = res
    data = {"compared": now(), "results": results}
    write_text(os.path.join(cdir, "compare.json"), json.dumps(data, indent=2))
    lines = ["Comparison of Before and After - %s" % data["compared"], ""]
    for sid, label in SECTIONS:
        res = results[sid]
        lines += ["=" * 78, label, "=" * 78]
        if res["error"]:
            lines.append("  " + res["error"])
        for name, c in res["cats"].items():
            lines.append("  %s (%d)" % (name, c["count"]))
            lines += ["    " + i for i in c["items"]]
            if c["count"] > len(c["items"]):
                lines.append("    ... %d more in %s" % (c["count"] - len(c["items"]), FULL_LIST.get(sid, "")))
        lines.append("")
    write_text(os.path.join(cdir, "compare.txt"), "\n".join(lines))
    return data


def kind_of(cat):
    if any(w in cat for w in ("removed", "deleted", "ended")):
        return "removed"
    if any(w in cat for w in ("changed", "modified")):
        return "changed"
    return "added"  # added, started, written, set, looked up, seen...


# --------------------------------------------------------------------
# PDF report (small built-in PDF writer, so nothing has to be installed)
# --------------------------------------------------------------------
def _jpeg_image(data):
    """A JPG goes into the PDF as it is; only its size and colour type are read here."""
    p = 2
    while p + 9 < len(data):
        if data[p] != 0xFF:
            p += 1
            continue
        m = data[p + 1]
        if m == 0xFF:
            p += 1
        elif m in (0x01, 0xD8) or 0xD0 <= m <= 0xD7:
            p += 2
        elif m in (0xC0, 0xC1, 0xC2):
            h, w, comps = int.from_bytes(data[p + 5:p + 7], "big"), int.from_bytes(data[p + 7:p + 9], "big"), data[p + 9]
            if comps not in (1, 3, 4) or not w or not h:
                break
            space = {1: "/DeviceGray", 3: "/DeviceRGB", 4: "/DeviceCMYK /Decode [1 0 1 0 1 0 1 0]"}[comps]
            return {"w": w, "h": h, "data": data,
                    "dict": "/ColorSpace %s /BitsPerComponent 8 /Filter /DCTDecode" % space}
        else:
            p += 2 + int.from_bytes(data[p + 2:p + 4], "big")
    raise ValueError("this JPG file could not be read")


def _png_image(data):
    """PNG logo -> PDF image. Transparent areas are shown white."""
    ihdr, plte, trns, idat, p = None, b"", None, [], 8
    while p + 8 <= len(data):
        n, kind = struct.unpack(">I4s", data[p:p + 8])
        body = data[p + 8:p + 8 + n]
        p += 12 + n
        if kind == b"IHDR":
            ihdr = body
        elif kind == b"PLTE":
            plte = body
        elif kind == b"tRNS":
            trns = body
        elif kind == b"IDAT":
            idat.append(body)
    if not ihdr or len(ihdr) < 13 or not idat:
        raise ValueError("this PNG file could not be read")
    w, h, depth, ctype, _c, _f, interlace = struct.unpack(">IIBBBBB", ihdr[:13])
    if ctype not in (0, 2, 3, 4, 6) or depth not in (1, 2, 4, 8, 16) or not w or not h:
        raise ValueError("this PNG file could not be read")
    if interlace:
        raise ValueError("interlaced PNG files are not supported - save the logo again without interlacing")
    if w * h > 4000000:
        raise ValueError("the logo is too large (%d x %d) - use a picture smaller than 2000 x 2000" % (w, h))
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ctype]
    raw = b"".join(idat)
    if ctype in (0, 2, 3) and trns is None and depth <= 8:
        # nothing transparent: the PNG's own compressed pixels can be used directly
        space = {0: "/DeviceGray", 2: "/DeviceRGB"}.get(ctype) or \
            "[/Indexed /DeviceRGB %d <%s>]" % (max(len(plte) // 3 - 1, 0), plte.hex())
        return {"w": w, "h": h, "data": raw,
                "dict": "/ColorSpace %s /BitsPerComponent %d /Filter /FlateDecode /DecodeParms << /Predictor 15 "
                        "/Colors %d /BitsPerComponent %d /Columns %d >>" % (space, depth, channels, depth, w)}
    # otherwise: unpack the pixels and blend transparent parts with white
    pix = zlib.decompress(raw)
    bpp, stride = max(1, channels * depth // 8), (w * channels * depth + 7) // 8
    if len(pix) < (stride + 1) * h:
        raise ValueError("this PNG file is damaged")
    top, out, prev, pos = (1 << depth) - 1, bytearray(), bytearray(stride), 0
    key = None
    if trns is not None and ctype in (0, 2):  # one colour is marked as transparent
        key = tuple(int.from_bytes(trns[i:i + 2], "big") for i in range(0, 2 * channels, 2))
    for _y in range(h):
        ftype, row = pix[pos], bytearray(pix[pos + 1:pos + 1 + stride])
        pos += 1 + stride
        if ftype == 1:
            for i in range(bpp, stride):
                row[i] = (row[i] + row[i - bpp]) & 255
        elif ftype == 2:
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 255
        elif ftype == 3:
            for i in range(stride):
                row[i] = (row[i] + (((row[i - bpp] if i >= bpp else 0) + prev[i]) >> 1)) & 255
        elif ftype == 4:
            for i in range(stride):
                a, b, c = (row[i - bpp], prev[i], prev[i - bpp]) if i >= bpp else (0, prev[i], 0)
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                row[i] = (row[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        prev = row
        if depth == 8:
            vals = row
        elif depth == 16:
            vals = [(row[i] << 8) | row[i + 1] for i in range(0, stride, 2)]
        else:
            vals = [(row[i * depth // 8] >> (8 - depth - (i * depth) % 8)) & top for i in range(w * channels)]
        for x in range(0, w * channels, channels):
            px, alpha = vals[x:x + channels], 255
            if ctype == 3:
                idx = px[0]
                rgb = tuple(plte[idx * 3:idx * 3 + 3]) if idx * 3 + 3 <= len(plte) else (0, 0, 0)
                alpha = trns[idx] if trns is not None and idx < len(trns) else 255
            else:
                if key is not None and tuple(px) == key:
                    alpha = 0
                colour = px[:channels - 1] if ctype in (4, 6) else px
                if ctype in (4, 6):
                    alpha = px[-1] * 255 // top
                colour = [v * 255 // top for v in colour]
                rgb = tuple(colour) if len(colour) == 3 else (colour[0],) * 3
            out += bytes(255 - (255 - v) * alpha // 255 for v in rgb)
    return {"w": w, "h": h, "data": zlib.compress(bytes(out)),
            "dict": "/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode"}


def load_logo(path):
    """Read a PNG or JPG so it can be placed in the PDF. Raises ValueError with a plain reason if it cannot."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ValueError("the logo file could not be opened (%s)" % e)
    try:
        if data[:2] == b"\xff\xd8":
            return _jpeg_image(data)
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return _png_image(data)
    except (struct.error, zlib.error, IndexError) as e:
        raise ValueError("the logo file is damaged (%s)" % e)
    raise ValueError("the logo must be a PNG or JPG picture")


class SimplePDF:
    W, H, M = 595.28, 841.89, 40
    FONTS = {"H": "Helvetica", "HB": "Helvetica-Bold", "C": "Courier", "CB": "Courier-Bold"}

    def __init__(self, footer=""):
        self.footer, self.pages, self.images = footer, [], {}
        self.new_page()

    def new_page(self):
        self.ops = []
        self.pages.append(self.ops)
        self.y = self.H - self.M

    def need(self, h):
        if self.y - h < self.M + 20:
            self.new_page()

    @staticmethod
    def _esc(s):
        s = re.sub(r"[\x00-\x1f]", " ", str(s)).encode("cp1252", "replace")
        return s.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")

    def put(self, x, y, s, font="H", size=10, color=(0, 0, 0), ops=None):
        op = ("BT /%s %g Tf %g %g %g rg %.2f %.2f Td (" % ((font, size) + tuple(color) + (x, y))).encode()
        (self.ops if ops is None else ops).append(op + self._esc(s) + b") Tj ET")

    def rect(self, x, y, w, h, color):
        self.ops.append(("%g %g %g rg %.2f %.2f %.2f %.2f re f" % (tuple(color) + (x, y, w, h))).encode())

    def image(self, img, x, y, w, h):
        """Place a picture from load_logo() with its bottom-left corner at x, y."""
        name = "Im%d" % (len(self.images) + 1)
        self.images[name] = img
        self.ops.append(("q %.2f 0 0 %.2f %.2f %.2f cm /%s Do Q" % (w, h, x, y, name)).encode())

    def line(self, s, font="H", size=10, color=(0, 0, 0), indent=0, gap=1.35):
        self.need(size * gap)
        self.y -= size * gap
        self.put(self.M + indent, self.y, s, font, size, color)

    def mono(self, s, size=7.5, indent=8, color=(0, 0, 0)):
        """Courier text, wrapped exactly (every Courier character is 0.6 x size wide)."""
        width = max(20, int((self.W - 2 * self.M - indent) / (0.6 * size)) - 2)
        s = re.sub(r"[\x00-\x1f]", " ", str(s))
        chunks = [s[i:i + width] for i in range(0, len(s), width)] or [""]
        for n, chunk in enumerate(chunks):
            self.line(("  " if n else "") + chunk, "C", size, color, indent, 1.3)

    def space(self, h):
        self.y -= h

    def save(self, path):
        objs = [b"", b""]
        nums = {}
        for key, base in self.FONTS.items():
            objs.append(("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>" % base).encode())
            nums[key] = len(objs)
        pics = {}
        for name, img in self.images.items():
            objs.append(("<< /Type /XObject /Subtype /Image /Width %d /Height %d %s /Length %d >>\nstream\n"
                         % (img["w"], img["h"], img["dict"], len(img["data"]))).encode() + img["data"] + b"\nendstream")
            pics[name] = len(objs)
        res = "<< /Font << %s >>" % " ".join("/%s %d 0 R" % kv for kv in nums.items())
        if pics:
            res += " /XObject << %s >>" % " ".join("/%s %d 0 R" % kv for kv in pics.items())
        res += " >>"
        kids = []
        for i, ops in enumerate(self.pages, 1):
            self.put(self.M, 24, self.footer, "H", 8, (0.4, 0.4, 0.4), ops)
            self.put(self.W - self.M - 60, 24, "Page %d of %d" % (i, len(self.pages)), "H", 8, (0.4, 0.4, 0.4), ops)
            stream = zlib.compress(b"\n".join(ops))
            objs.append(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream")
            objs.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources %s /Contents %d 0 R >>"
                         % (self.W, self.H, res, len(objs))).encode())
            kids.append(len(objs))
        objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
        objs[1] = ("<< /Type /Pages /Count %d /Kids [%s] >>"
                   % (len(kids), " ".join("%d 0 R" % k for k in kids))).encode()
        out, offs = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"), []
        for n, body in enumerate(objs, 1):
            offs.append(len(out))
            out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        out += b"".join(b"%010d 00000 n \n" % o for o in offs)
        out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
        with open(path, "wb") as f:
            f.write(out)


KIND_COLOR = {"added": (0.05, 0.45, 0.15), "removed": (0.7, 0.1, 0.1), "changed": (0.7, 0.42, 0.0)}


def generate_report(project_dir):
    cmp_data = load_json(os.path.join(project_dir, "Compare", "compare.json"))
    if not cmp_data:
        raise RuntimeError("No comparison found. Click Compare first.")
    proj = load_json(os.path.join(project_dir, "project.json"), {})
    snap = {ph: load_json(os.path.join(project_dir, ph, "snapshot_info.json"), {}) for ph in ("Before", "After")}
    live = load_live(project_dir)
    name = proj.get("name") or os.path.basename(project_dir)
    pdf = SimplePDF(" - ".join(x for x in (ORG_NAME, SANDBOX_NAME, "project %s" % name, "generated %s" % now()) if x))
    M, W = pdf.M, pdf.W - 2 * pdf.M

    logo = None
    if LOGO_FILE:
        try:
            logo = load_logo(LOGO_FILE)
        except ValueError:
            pass  # a missing or unreadable logo must not stop the report
    if ORG_NAME or logo:  # organisation on the left, logo on the right, above the title bar
        lw = lh = 0
        if logo:
            scale = min(150.0 / logo["w"], 48.0 / logo["h"])
            lw, lh = logo["w"] * scale, logo["h"] * scale
            pdf.image(logo, M + W - lw, pdf.y - lh, lw, lh)
        band = max(lh, 22)
        if ORG_NAME:
            room = int((W - lw - 12) / 7.9)  # about how many bold 14pt letters fit beside the logo
            pdf.put(M, pdf.y - band / 2 - 5, ORG_NAME if len(ORG_NAME) <= room else ORG_NAME[:room - 3] + "...",
                    "HB", 14)
        pdf.space(band + 10)

    pdf.rect(M, pdf.y - 34, W, 34, (0.78, 0.78, 0.78))
    pdf.put(M + 10, pdf.y - 23, "%s - Analysis Report" % SANDBOX_NAME, "HB", 16)
    pdf.space(46)
    recording = ", ".join("%s: %s" % (label.split(" (")[0], live_state(live, key)) for key, label in LIVE_ITEMS)
    facts = [("Organisation", ORG_NAME), ("Analyst", ANALYST)]
    facts = [f for f in facts if f[1]]
    facts += [("Project", name), ("File tested", proj.get("sample", "(not set)")),
             ("SHA-256", proj.get("sha256", "")), ("File size", "%s bytes" % proj.get("size", "")),
             ("1st shot (Before)", snap["Before"].get("finished", "")), ("Install/Run", proj.get("run_time", "")),
             ("Live recording", recording if live else "not recorded"),
             ("2nd shot (After)", snap["After"].get("finished", "")), ("Compared", cmp_data.get("compared", "")),
             ("Machine", "%s (%s)" % (platform.node(), platform.platform()))]
    for k, v in facts:
        pdf.need(13)
        pdf.y -= 13
        pdf.put(M, pdf.y, k, "HB", 9)
        text = str(v)
        pdf.put(M + 105, pdf.y, text[:84], "C", 8.5)
        for i in range(84, len(text), 84):
            pdf.y -= 11
            pdf.put(M + 105, pdf.y, text[i:i + 84], "C", 8.5)

    pdf.space(18)
    pdf.line("Summary", "HB", 12)
    pdf.space(6)
    cols = [("Check", 6), ("Added / new", 250), ("Removed", 330), ("Changed", 395), ("Note", 455)]
    pdf.need(18 * (len(SECTIONS) + 1))
    pdf.rect(M, pdf.y - 16, W, 16, (0.78, 0.78, 0.78))
    for title, x in cols:
        pdf.put(M + x, pdf.y - 11.5, title, "HB", 9)
    pdf.space(16)
    empty = {"error": "no data", "cats": {}}
    for n, (sid, label) in enumerate(SECTIONS):
        res = cmp_data["results"].get(sid, empty)
        tot = Counter()
        for cat, c in res["cats"].items():
            tot[kind_of(cat)] += c["count"]
        if n % 2:
            pdf.rect(M, pdf.y - 16, W, 16, (0.94, 0.94, 0.94))
        pdf.put(M + 6, pdf.y - 11.5, label, "H", 9)
        if res["error"]:
            pdf.put(M + 250, pdf.y - 11.5, res["error"][:60], "H", 8, (0.5, 0.5, 0.5))
        else:
            for kind, x in (("added", 250), ("removed", 330), ("changed", 395)):
                pdf.put(M + x, pdf.y - 11.5, str(tot[kind]), "HB" if tot[kind] else "H", 9,
                        KIND_COLOR[kind] if tot[kind] else (0.45, 0.45, 0.45))
            state = snap["After"].get("tools", {}).get(sid, {}).get("state", "")
            if state and state != "done":
                pdf.put(M + 455, pdf.y - 11.5, state, "H", 8, (0.5, 0.5, 0.5))
        pdf.space(16)

    notes = {"live": "File and registry activity is listed for processes that started during the recording; "
                     "network activity is listed for every process.",
             "network": "From the Windows DNS cache and the packet capture (Live\\network.pcapng, opens in "
                        "Wireshark)."}
    for sid, label in SECTIONS:
        res = cmp_data["results"].get(sid, empty)
        pdf.space(14)
        pdf.need(60)
        pdf.line(label, "HB", 12)
        pdf.rect(M, pdf.y - 4, W, 0.8, (0.5, 0.5, 0.5))
        pdf.space(6)
        if res["error"]:
            pdf.line(res["error"], "H", 9, (0.5, 0.5, 0.5))
            continue
        if sid in notes:
            pdf.line(notes[sid], "H", 8, (0.4, 0.4, 0.4))
            pdf.space(2)
        if not any(c["count"] for c in res["cats"].values()):
            pdf.line("Nothing recorded." if sid in notes else "No changes detected.", "H", 9, (0.4, 0.4, 0.4))
            continue
        for cat, c in res["cats"].items():
            if not c["count"]:
                continue
            pdf.need(30)
            pdf.line("%s (%d)" % (cat[0].upper() + cat[1:], c["count"]), "HB", 9.5, KIND_COLOR[kind_of(cat)])
            for item in c["items"][:MAX_ITEMS]:
                pdf.mono(item)
            more = c["count"] - min(len(c["items"]), MAX_ITEMS)
            if more > 0:
                pdf.line("... %d more - full list in Compare\\%s" % (more, FULL_LIST.get(sid, "compare.txt")),
                         "H", 8, (0.4, 0.4, 0.4), 8)
            pdf.space(4)

    out = os.path.join(project_dir, "%s_Report.pdf" % name)
    pdf.save(out)
    return out


# --------------------------------------------------------------------
# Running the file under test
# --------------------------------------------------------------------
def launch_sample(path):
    ext = os.path.splitext(path)[1].lower()
    cwd = os.path.dirname(path) or None
    if ext == ".msi":
        return subprocess.Popen(["msiexec", "/i", path], cwd=cwd).pid
    if ext in (".bat", ".cmd"):
        return subprocess.Popen(["cmd", "/c", path], cwd=cwd).pid
    try:
        return subprocess.Popen([path], cwd=cwd).pid
    except OSError:
        os.startfile(path)  # lets Windows handle it (e.g. a file that asks for elevation)
        return None


# --------------------------------------------------------------------
# Dashboard window
# --------------------------------------------------------------------
GREY, FONT = "#bdbdbd", "Segoe UI"
GREEN, AMBER, RED, BLUE = "#0a7a2a", "#a06a00", "#b01818", "#0b5cad"
MARKS = {"pending": ("\u2022", "#888888"), "running": ("\u25ba", BLUE), "done": ("\u2713", GREEN),
         "skipped": ("\u2013", AMBER), "failed": ("\u2717", RED),
         "recording": ("\u25cf", RED), "stopped": ("\u25ba", BLUE)}
WORDS = {"pending": "", "running": "running...", "done": "Done", "skipped": "Skipped", "failed": "Failed",
         "recording": "Recording", "stopped": "saving..."}


class Dashboard:
    def __init__(self, root):
        self.root, self.q = root, queue.Queue()
        self.project_dir, self.busy = None, False
        self.marks = {"Before": {}, "After": {}, "Live": {}}
        self.words = {"Before": {}, "After": {}, "Live": {}}
        self.shot_lbl = {}
        self.buttons = []
        self.build()
        if hasattr(root, "protocol"):
            root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self.pump)

    # ---- layout -------------------------------------------------
    def button(self, parent, text, cmd, width=None):
        b = tk.Button(parent, text=text, command=cmd, bg=GREY, activebackground="#a9a9a9", relief="raised",
                      bd=1, font=(FONT, 11), padx=14, pady=5, width=width)
        self.buttons.append(b)
        return b

    def checklist(self, parent, group, items, bold=True):
        box = tk.Frame(parent, bg="white")
        for n, (tid, label) in enumerate(items):
            mark = tk.Label(box, text=MARKS["pending"][0], fg=MARKS["pending"][1], bg="white",
                            font=(FONT, 12, "bold"), width=2)
            mark.grid(row=n, column=0)
            tk.Label(box, text=label, bg="white",
                     font=(FONT, 11, "bold") if bold else (FONT, 10)).grid(row=n, column=1, sticky="w")
            word = tk.Label(box, text="", bg="white", font=(FONT, 10), width=10, anchor="w")
            word.grid(row=n, column=2, sticky="w", padx=(12, 0))
            self.marks[group][tid], self.words[group][tid] = mark, word
        if group != "Live":  # one line under the list that says the whole shot is finished
            self.shot_lbl[group] = tk.Label(box, text="", bg="white", font=(FONT, 10, "bold"), anchor="w")
            self.shot_lbl[group].grid(row=len(items), column=0, columnspan=3, sticky="w", pady=(6, 0))
        return box

    def build(self):
        r = self.root
        r.title(SANDBOX_NAME)
        r.configure(bg="white")
        r.minsize(1060, 760)
        self.title_lbl = tk.Label(r, text=SANDBOX_NAME, bg=GREY, font=(FONT, 14, "bold"), relief="solid", bd=1,
                                  pady=8)
        self.title_lbl.pack(fill="x", padx=40, pady=(16, 14))

        row = tk.Frame(r, bg="white")
        row.pack(fill="x", padx=60, pady=6)
        self.button(row, "Create a project", self.create_project, 18).pack(side="left")
        self.project_var = tk.StringVar(value="Test")
        tk.Entry(row, textvariable=self.project_var, font=(FONT, 12), justify="center", relief="solid",
                 bd=1).pack(side="left", fill="x", expand=True, padx=(14, 20), ipady=5)
        self.button(row, "Settings", self.open_settings).pack(side="left")

        row = tk.Frame(r, bg="white")
        row.pack(fill="x", padx=60, pady=(16, 6))
        self.sample_var = tk.StringVar()
        tk.Entry(row, textvariable=self.sample_var, font=(FONT, 12), justify="center", relief="solid",
                 bd=1).pack(side="left", fill="x", expand=True, ipady=5)
        self.button(row, "Browse for PE / MSI", self.browse).pack(side="left", padx=(20, 0))

        mid = tk.Frame(r, bg="white")
        mid.pack(fill="x", padx=60, pady=6)
        for c in range(3):
            mid.columnconfigure(c, weight=1)
        shots = [(t[0], t[1]) for t in TOOLS]
        left = tk.Frame(mid, bg="white")
        left.grid(row=0, column=0, sticky="nw")
        self.button(left, "Run Sand Box Tool for 1st shot", lambda: self.shot("Before")).pack(anchor="w")
        self.checklist(left, "Before", shots).pack(anchor="w", padx=16, pady=8)
        centre = tk.Frame(mid, bg="white")
        centre.grid(row=0, column=1)
        self.button(centre, "Install/Run", self.install_run).pack()
        tk.Label(centre, text="Recorded while it runs:", bg="white", fg="#555555",
                 font=(FONT, 9, "italic")).pack(pady=(14, 2))
        self.checklist(centre, "Live", LIVE_ITEMS, bold=False).pack()
        right = tk.Frame(mid, bg="white")
        right.grid(row=0, column=2, sticky="ne")
        self.button(right, "Run Sand Box Tool for 2nd shot", lambda: self.shot("After")).pack(anchor="e")
        self.checklist(right, "After", shots).pack(anchor="w", padx=16, pady=8)

        row = tk.Frame(r, bg="white")
        row.pack(fill="x", padx=60, pady=(4, 10))
        for c in range(3):
            row.columnconfigure(c, weight=1, uniform="b")
        self.button(row, "Compare", self.compare).grid(row=0, column=0, sticky="w")
        self.button(row, "Generate Report", self.report).grid(row=0, column=1)
        self.button(row, "Open project folder", self.open_folder).grid(row=0, column=2, sticky="e")
        self.compare_lbl = tk.Label(row, text="", bg="white", font=(FONT, 10, "bold"), anchor="w")
        self.compare_lbl.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        self.status = tk.Label(r, text="Start by creating a project.", bg="white", fg="#333333", anchor="w",
                               font=(FONT, 10, "italic"))
        self.status.pack(fill="x", padx=40)
        self.logbox = scrolledtext.ScrolledText(r, height=8, font=("Consolas", 9), state="disabled",
                                                relief="solid", bd=1)
        self.logbox.pack(fill="both", expand=True, padx=40, pady=(4, 16))

    # ---- plumbing -----------------------------------------------
    def log(self, text):
        self.q.put(("log", text))

    def pump(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "log":
                    self.logbox.configure(state="normal")
                    self.logbox.insert("end", msg[1] + "\n")
                    self.logbox.see("end")
                    self.logbox.configure(state="disabled")
                elif msg[0] == "mark":
                    self.set_mark(msg[1], msg[2], msg[3])
                elif msg[0] == "finish":
                    self.set_busy(False, msg[1])
                    if msg[2]:
                        msg[2]()
        except queue.Empty:
            pass
        self.root.after(100, self.pump)

    def set_mark(self, group, tid, state):
        ch, color = MARKS.get(state, MARKS["pending"])
        self.marks[group][tid].configure(text=ch, fg=color)
        self.words[group][tid].configure(text=WORDS.get(state, ""), fg=color)

    def mark_live(self, key, state):
        self.q.put(("mark", "Live", key, state))

    def show_shot(self, phase, info):
        """Line under the checklist: is the whole shot done?"""
        tools = (info or {}).get("tools")
        if not tools:
            self.shot_lbl[phase].configure(text="")
            return
        nth = "1st" if phase == "Before" else "2nd"
        n = Counter(t.get("state") for t in tools.values())
        if n["done"] == len(TOOLS):
            self.shot_lbl[phase].configure(text="\u2713 %s shot done" % nth, fg=GREEN)
        else:
            self.shot_lbl[phase].configure(fg=AMBER, text="%s shot finished: %d done, %d skipped, %d failed"
                                           % (nth, n["done"], n["skipped"], n["failed"]))

    def show_compared(self, data):
        """Line under the Compare button. Returns the message that is shown."""
        if not data:
            self.compare_lbl.configure(text="")
            return ""
        results = data.get("results", {}).values()
        failed = sum(1 for r in results if r.get("error") and not r.get("skipped"))
        skipped = sum(1 for r in results if r.get("skipped"))
        if failed:
            text, color = "Compared - %d check(s) could not be compared (see the log)" % failed, AMBER
        else:
            text, color = "\u2713 Compared successfully", GREEN
            if skipped:
                text += " (%d check(s) were not captured, so they were skipped)" % skipped
        self.compare_lbl.configure(text=text, fg=color)
        return text

    def set_busy(self, busy, status):
        self.busy = busy
        self.status.configure(text=status)
        for b in self.buttons:
            b.configure(state="disabled" if busy else "normal")

    def background(self, status, work, done_status, after=None):
        """Run work() off the window thread so the dashboard stays responsive."""
        self.set_busy(True, status)

        def runner():
            try:
                result = work()
                self.q.put(("finish", done_status, (lambda: after(result)) if after else None))
            except Exception as e:
                err = "%s: %s" % (type(e).__name__, e)
                self.log("ERROR - " + err)
                self.q.put(("finish", "Failed: " + err, lambda: messagebox.showerror(SANDBOX_NAME, err)))

        threading.Thread(target=runner, daemon=True).start()

    def need_project(self):
        if not self.project_dir:
            messagebox.showwarning(SANDBOX_NAME, "Create a project first.")
            return False
        return True

    def save_project(self, **changes):
        path = os.path.join(self.project_dir, "project.json")
        data = load_json(path, {})
        data.update(changes)
        write_text(path, json.dumps(data, indent=2))
        return data

    def on_close(self):
        if self.busy and not messagebox.askyesno(SANDBOX_NAME, "Work is still running.\n\nClose anyway?"):
            return
        if self.project_dir and needs_stop(load_live(self.project_dir)):
            if not messagebox.askyesno(SANDBOX_NAME, "The live recording is still running.\n\n"
                                                     "Stop the recording and close the dashboard?"):
                return
            try:
                stop_recording(self.project_dir, lambda s: None, lambda k, s: None)
            except Exception:
                pass
        self.root.destroy()

    # ---- buttons ------------------------------------------------
    def create_project(self):
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", self.project_var.get().strip()).strip(". ")
        if not name:
            messagebox.showwarning(SANDBOX_NAME, "Type a project name first.")
            return
        folder = os.path.join(desktop_dir(), name)
        if os.path.isdir(folder) and not messagebox.askyesno(
                SANDBOX_NAME, "A folder named '%s' is already on the Desktop.\n\nOpen it and carry on?" % name):
            return
        os.makedirs(folder, exist_ok=True)
        self.project_dir = folder
        self.project_var.set(name)
        data = self.save_project(name=name)
        if "created" not in data:
            data = self.save_project(created=now())
        if data.get("sample"):
            self.sample_var.set(data["sample"])
        for phase in ("Before", "After"):
            info = load_json(os.path.join(folder, phase, "snapshot_info.json"), {})
            for tid, _, _ in TOOLS:
                self.set_mark(phase, tid, info.get("tools", {}).get(tid, {}).get("state", "pending"))
            self.show_shot(phase, info)
        live = load_live(folder)
        for key, _ in LIVE_ITEMS:
            self.set_mark("Live", key, live_state(live, key))
        self.show_compared(load_json(os.path.join(folder, "Compare", "compare.json")))
        self.status.configure(text="Project folder: " + folder)
        self.log("[%s] Project ready: %s" % (now(), folder))

    def browse(self):
        path = filedialog.askopenfilename(title="Browse for PE / MSI", filetypes=[
            ("Programs and installers", "*.exe *.msi *.dll *.scr *.com *.bat *.cmd"), ("All files", "*.*")])
        if path:
            self.sample_var.set(os.path.normpath(path))

    def shot(self, phase):
        if self.busy or not self.need_project():
            return
        if phase == "After":
            if not os.path.isfile(os.path.join(self.project_dir, "Before", "snapshot_info.json")):
                messagebox.showwarning(SANDBOX_NAME, "Take the 1st shot first.")
                return
            if not load_json(os.path.join(self.project_dir, "project.json"), {}).get("run_time") and \
                    not messagebox.askyesno(SANDBOX_NAME, "Install/Run has not been clicked yet.\n\n"
                                                          "Take the 2nd shot anyway?"):
                return
        if os.path.isfile(os.path.join(self.project_dir, phase, "snapshot_info.json")) and \
                not messagebox.askyesno(SANDBOX_NAME, "The '%s' shot already exists. Replace it?" % phase):
            return
        for tid, _, _ in TOOLS:
            self.set_mark(phase, tid, "pending")
        self.show_shot(phase, None)
        self.show_compared(None)  # an earlier comparison no longer matches the shots
        nth = "1st" if phase == "Before" else "2nd"
        self.log("[%s] %s shot started (folder: %s)" % (now(), nth, phase))
        pdir = self.project_dir

        def work():
            if needs_stop(load_live(pdir)):  # stop recording first, so the shot's own work is not recorded
                self.log("  Stopping the live recording")
                stop_recording(pdir, self.log, self.mark_live)
            info = take_snapshot(pdir, phase, self.log, lambda tid, st: self.q.put(("mark", phase, tid, st)))
            finish_recording(pdir, self.log, self.mark_live)
            return info

        self.background("Taking the %s shot - the registry, file and Autoruns steps take a few minutes..." % nth,
                        work, "%s shot saved in the %s folder." % (nth, phase),
                        lambda info: (self.show_shot(phase, info),
                                      self.log("[%s] %s shot finished" % (now(), nth))))

    def install_run(self):
        if self.busy or not self.need_project():
            return
        path = self.sample_var.get().strip().strip('"')
        if not os.path.isfile(path):
            messagebox.showwarning(SANDBOX_NAME, "Browse for the PE / MSI file first.")
            return
        if not os.path.isfile(os.path.join(self.project_dir, "Before", "snapshot_info.json")) and \
                not messagebox.askyesno(SANDBOX_NAME, "The 1st shot has not been taken yet.\n\nRun the file anyway?"):
            return
        if not messagebox.askyesno(SANDBOX_NAME, "This will run:\n\n%s\n\non THIS machine. Only continue inside "
                                                 "the sandbox VM.\n\nRun it now?" % path):
            return
        pdir = self.project_dir

        def work():
            self.save_project(sample=path, sha256=sha256_file(path), size=os.path.getsize(path))
            if LIVE_RECORDING and not needs_stop(load_live(pdir)):  # already recording = just start the file
                self.log("[%s] Starting the live recording" % now())
                for key, _ in LIVE_ITEMS:
                    self.mark_live(key, "pending")
                start_recording(pdir, self.log, self.mark_live)
            pid = launch_sample(path)
            self.save_project(run_time=now())
            self.log("[%s] Started %s%s" % (now(), path, " (PID %d)" % pid if pid else ""))

        self.background("Starting the live recording, then the file...", work,
                        "File started. Finish the install / let it run, then take the 2nd shot.")

    def compare(self):
        if self.busy or not self.need_project():
            return
        for phase in ("Before", "After"):
            if not os.path.isfile(os.path.join(self.project_dir, phase, "snapshot_info.json")):
                messagebox.showwarning(SANDBOX_NAME, "The '%s' shot is missing. Take both shots first." % phase)
                return
        self.log("[%s] Comparing Before and After" % now())
        pdir = self.project_dir
        self.show_compared(None)

        def done(data):
            text = self.show_compared(data).replace("\u2713 ", "")
            self.log("[%s] %s" % (now(), text))
            messagebox.showinfo(SANDBOX_NAME, text + ".\n\nResults are in the Compare folder. "
                                                     "Now click Generate Report.")

        self.background("Comparing...", lambda: run_compare(pdir, self.log),
                        "Compared. Results are in the Compare folder. Now click Generate Report.", done)

    def report(self):
        if self.busy or not self.need_project():
            return
        pdir = self.project_dir

        def done(path):
            self.log("[%s] Report written: %s" % (now(), path))
            if os.name == "nt":
                os.startfile(path)

        self.background("Writing the PDF report...", lambda: generate_report(pdir), "Report created.", done)

    def open_folder(self):
        if self.need_project() and os.name == "nt":
            os.startfile(self.project_dir)

    def open_settings(self):
        if not self.busy:
            SettingsWindow(self)

    def settings_changed(self):
        self.root.title(SANDBOX_NAME)
        self.title_lbl.configure(text=SANDBOX_NAME)
        self.log("[%s] Settings saved" % now())


TOOL_NAMES = [("CurrPorts", ("cports.exe",)), ("Autoruns", ("autorunsc64.exe", "autorunsc.exe")),
              ("Procmon", ("Procmon64.exe", "Procmon.exe"))]


class SettingsWindow:
    """Form for the values in the SETTINGS block. Save writes sandbox_settings.json next to the script."""

    def __init__(self, dash):
        self.dash = dash
        w = self.win = tk.Toplevel(dash.root)
        w.title("%s - Settings" % SANDBOX_NAME)
        w.configure(bg="white", padx=18, pady=14)
        w.resizable(False, False)
        w.transient(dash.root)
        self.vars, self.texts, self.row = {}, {}, 0

        self.heading("On the dashboard and the report")
        self.entry("SANDBOX_NAME", "Sandbox title")
        self.entry("ORG_NAME", "Organisation name")
        self.entry("ANALYST", "Analyst name")
        self.entry("LOGO_FILE", "Logo for the report", browse=self.pick_logo, hint="PNG or JPG. Leave empty for no logo.")

        self.heading("Tools")
        self.entry("TOOLS_DIR", "Tools folder", browse=self.pick_tools)
        self.tools_lbl = tk.Label(w, text="", bg="white", font=(FONT, 9), anchor="w", justify="left")
        self.tools_lbl.grid(row=self.row, column=1, columnspan=2, sticky="w")
        self.row += 1

        self.heading("File check")
        self.textbox("FILE_ROOTS", "Folders to watch", "One folder per line.", height=5)
        self.textbox("FILE_EXCLUDE", "Folders to leave out", "One folder per line. The project folder is always left out.", height=2)

        self.heading("Recording and report")
        self.check("LIVE_RECORDING", "Record with Procmon and packet capture while the file runs")
        self.check("KEEP_RAW_CAPTURES", "Keep the large raw recording files (.pml and .etl)")
        self.entry("MAX_ITEMS", "Lines per category in the report", width=8)

        bar = tk.Frame(w, bg="white")
        bar.grid(row=self.row, column=0, columnspan=3, sticky="e", pady=(16, 0))
        for text, cmd in (("Reset to defaults", lambda: self.fill(DEFAULTS)), ("Cancel", w.destroy), ("Save", self.save)):
            tk.Button(bar, text=text, command=cmd, bg=GREY, activebackground="#a9a9a9", relief="raised", bd=1,
                      font=(FONT, 10), padx=14, pady=4).pack(side="left", padx=(8, 0))
        self.fill(current_settings())
        try:
            w.grab_set()  # keep the dashboard behind until this window is closed
        except tk.TclError:
            pass

    # ---- building blocks ----
    def heading(self, text):
        tk.Label(self.win, text=text, bg="white", font=(FONT, 10, "bold"), anchor="w").grid(
            row=self.row, column=0, columnspan=3, sticky="w", pady=(12 if self.row else 0, 4))
        self.row += 1

    def label(self, text):
        tk.Label(self.win, text=text, bg="white", font=(FONT, 10), anchor="w").grid(
            row=self.row, column=0, sticky="nw", padx=(10, 12), pady=3)

    def hint(self, text):
        if text:
            self.row += 1
            tk.Label(self.win, text=text, bg="white", fg="#666666", font=(FONT, 8), anchor="w").grid(
                row=self.row, column=1, columnspan=2, sticky="w")

    def entry(self, key, text, browse=None, hint="", width=58):
        self.label(text)
        self.vars[key] = tk.StringVar()
        tk.Entry(self.win, textvariable=self.vars[key], font=(FONT, 10), relief="solid", bd=1, width=width).grid(
            row=self.row, column=1, sticky="w", pady=3, ipady=2)
        if browse:
            tk.Button(self.win, text="Browse...", command=browse, bg=GREY, relief="raised", bd=1,
                      font=(FONT, 9), padx=8).grid(row=self.row, column=2, padx=(8, 0))
        self.hint(hint)
        self.row += 1

    def textbox(self, key, text, hint="", height=5):
        self.label(text)
        self.texts[key] = scrolledtext.ScrolledText(self.win, font=("Consolas", 9), relief="solid", bd=1, width=60,
                                                    height=height, wrap="none")
        self.texts[key].grid(row=self.row, column=1, columnspan=2, sticky="w", pady=3)
        self.hint(hint)
        self.row += 1

    def check(self, key, text):
        self.vars[key] = tk.BooleanVar()
        tk.Checkbutton(self.win, text=text, variable=self.vars[key], bg="white", activebackground="white",
                       font=(FONT, 10), anchor="w").grid(row=self.row, column=0, columnspan=3, sticky="w", padx=(6, 0))
        self.row += 1

    # ---- behaviour ----
    def fill(self, values):
        for key, var in self.vars.items():
            var.set(values[key])
        for key, box in self.texts.items():
            box.delete("1.0", "end")
            box.insert("1.0", "\n".join(values[key]))
        self.show_tools()

    def show_tools(self):
        folder = self.vars["TOOLS_DIR"].get().strip()
        found = [name for name, files in TOOL_NAMES if find_tool(*files, tools_dir=folder or None)]
        missing = [name for name, _ in TOOL_NAMES if name not in found]
        text = "Found: %s" % (", ".join(found) or "none")
        if missing:
            text += "     Not found: %s" % ", ".join(missing)
        self.tools_lbl.configure(text=text, fg=AMBER if missing else GREEN)

    def pick_logo(self):
        path = filedialog.askopenfilename(parent=self.win, title="Logo for the report",
                                          filetypes=[("Pictures", "*.png *.jpg *.jpeg"), ("All files", "*.*")])
        if path:
            self.vars["LOGO_FILE"].set(os.path.normpath(path))

    def pick_tools(self):
        path = filedialog.askdirectory(parent=self.win, title="Tools folder")
        if path:
            self.vars["TOOLS_DIR"].set(os.path.normpath(path))
            self.show_tools()

    def collect(self):
        """Read the form. Returns the settings, or raises ValueError with a message for the user."""
        v = {k: (var.get().strip() if isinstance(var, tk.StringVar) else bool(var.get()))
             for k, var in self.vars.items()}
        for key, box in self.texts.items():
            v[key] = [line.strip().strip('"') for line in box.get("1.0", "end").splitlines() if line.strip()]
        if not v["SANDBOX_NAME"]:
            raise ValueError("The sandbox title cannot be empty.")
        if not v["TOOLS_DIR"]:
            raise ValueError("Choose the tools folder.")
        if not v["FILE_ROOTS"]:
            raise ValueError("List at least one folder to watch.")
        try:
            v["MAX_ITEMS"] = int(v["MAX_ITEMS"])
        except ValueError:
            v["MAX_ITEMS"] = 0
        if not 10 <= v["MAX_ITEMS"] <= 5000:
            raise ValueError("Lines per category must be a number from 10 to 5000.")
        v["LOGO_FILE"] = v["LOGO_FILE"].strip('"')
        if v["LOGO_FILE"]:
            try:
                load_logo(v["LOGO_FILE"])
            except ValueError as e:
                raise ValueError("The logo cannot be used: %s." % e)
        return v

    def save(self):
        try:
            values = self.collect()
        except ValueError as e:
            messagebox.showerror(SANDBOX_NAME, str(e), parent=self.win)
            return
        if not os.path.isdir(values["TOOLS_DIR"]) and not messagebox.askyesno(
                SANDBOX_NAME, "The tools folder does not exist:\n%s\n\nSave anyway?" % values["TOOLS_DIR"],
                parent=self.win):
            return
        try:
            save_settings(values)
        except OSError as e:
            messagebox.showerror(SANDBOX_NAME, "The settings could not be saved:\n%s" % e, parent=self.win)
            return
        self.win.destroy()
        self.dash.settings_changed()


def main():
    if tk is None:
        sys.exit("Tkinter is missing. Reinstall Python from python.org with 'tcl/tk and IDLE' ticked.")
    load_settings()
    root = tk.Tk()
    if not is_admin():
        if messagebox.askyesno(SANDBOX_NAME, "The registry and Autoruns checks need Administrator rights.\n\n"
                                             "Restart the dashboard as Administrator?"):
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                '"%s"' % os.path.abspath(__file__), None, 1)
            return
    Dashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
