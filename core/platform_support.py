#!/usr/bin/env python3
"""
ArgusML Windows Support Module
Handles Windows-specific paths, services, and compatibility.
"""

import os
import sys
import platform

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

def get_eve_log_path():
    """Get Suricata eve.json path for current platform."""
    if IS_WINDOWS:
        return r"C:\Program Files\Suricata\log\eve.json"
    elif IS_MAC:
        return "/usr/local/var/log/suricata/eve.json"
    else:
        return "/var/log/suricata/eve.json"

def get_rules_path():
    """Get Suricata rules path for current platform."""
    if IS_WINDOWS:
        return r"C:\Program Files\Suricata\rules\argus_ml.rules"
    elif IS_MAC:
        return "/usr/local/var/lib/suricata/rules/argus_ml.rules"
    else:
        return "/var/lib/suricata/rules/argus_ml.rules"

def get_models_dir():
    """Get models directory for current platform."""
    if IS_WINDOWS:
        return os.path.join(os.environ.get("APPDATA", "C:\\ArgusML"), "ArgusML", "models")
    else:
        home = os.path.expanduser("~")
        return os.path.join(home, "argusml", "models")

def get_datasets_dir():
    """Get datasets directory for current platform."""
    if IS_WINDOWS:
        return os.path.join(os.environ.get("APPDATA", "C:\\ArgusML"), "ArgusML", "datasets")
    else:
        home = os.path.expanduser("~")
        return os.path.join(home, "argusml", "datasets")

def get_output_dir():
    """Get output directory for current platform."""
    if IS_WINDOWS:
        return os.path.join(os.environ.get("APPDATA", "C:\\ArgusML"), "ArgusML", "output")
    else:
        home = os.path.expanduser("~")
        return os.path.join(home, "argusml", "output")

def reload_suricata():
    """Reload Suricata rules for current platform."""
    import subprocess
    if IS_WINDOWS:
        try:
            subprocess.run(
                ["sc", "stop", "suricata"],
                capture_output=True
            )
            subprocess.run(
                ["sc", "start", "suricata"],
                capture_output=True
            )
            print("[platform] Suricata restarted on Windows")
        except Exception as e:
            print(f"[platform] Windows Suricata restart error: {e}")
    else:
        try:
            result = subprocess.run(
                ["pidof", "suricata"],
                capture_output=True, text=True
            )
            pid = result.stdout.strip()
            if pid:
                subprocess.run(["kill", "-USR2", pid], check=True)
                print(f"[platform] Suricata reloaded (pid {pid})")
        except Exception as e:
            print(f"[platform] Suricata reload error: {e}")

def tail_file(filepath, callback, poll_interval=5):
    """
    Cross-platform file tailing.
    Uses tail on Linux/Mac, polling on Windows.
    """
    import time
    import json

    if IS_WINDOWS:
        # Windows: use polling
        print(f"[platform] Windows polling mode for {filepath}")
        last_position = 0
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)
                last_position = f.tell()

        while True:
            try:
                if os.path.exists(filepath):
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_position)
                        lines = f.readlines()
                        last_position = f.tell()

                    events = []
                    for line in lines:
                        try:
                            event = json.loads(line.strip())
                            events.append(event)
                        except:
                            continue

                    if events:
                        callback(events)

            except Exception as e:
                print(f"[platform] Polling error: {e}")

            time.sleep(poll_interval)
    else:
        # Linux/Mac: use tail -F
        import subprocess
        import select

        process = subprocess.Popen(
            ["tail", "-F", "-n", "0", filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        buffer = []
        last_process_time = time.time()

        try:
            while True:
                ready = select.select([process.stdout], [], [], 0.5)
                if ready[0]:
                    line = process.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                event = json.loads(line)
                                buffer.append(event)
                            except:
                                continue

                now = time.time()
                if buffer and (now - last_process_time) >= poll_interval:
                    callback(buffer)
                    buffer = []
                    last_process_time = now

        except KeyboardInterrupt:
            process.terminate()
            raise

def install_windows_service():
    """Install ArgusML as a Windows service."""
    if not IS_WINDOWS:
        print("[platform] Not on Windows")
        return

    service_script = os.path.join(os.path.dirname(__file__), "..", "argus_ml.py")
    python_exe = sys.executable

    try:
        import subprocess
        # Create scheduled task as alternative to Windows service
        subprocess.run([
            "schtasks", "/create",
            "/tn", "ArgusML",
            "/tr", f'"{python_exe}" "{service_script}"',
            "/sc", "onstart",
            "/ru", "SYSTEM",
            "/f"
        ], check=True)
        print("[platform] ArgusML scheduled task created — runs on startup")
    except Exception as e:
        print(f"[platform] Windows service install error: {e}")
        print("[platform] To run manually: python argus_ml.py")

def get_platform_info():
    """Return platform information."""
    return {
        "platform": platform.system(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version,
        "is_windows": IS_WINDOWS,
        "is_linux": IS_LINUX,
        "is_mac": IS_MAC,
        "eve_log": get_eve_log_path(),
        "rules_path": get_rules_path(),
        "models_dir": get_models_dir(),
    }

if __name__ == "__main__":
    info = get_platform_info()
    print(f"Platform: {info['platform']}")
    print(f"Eve log: {info['eve_log']}")
    print(f"Rules path: {info['rules_path']}")
    print(f"Models dir: {info['models_dir']}")
    print("ArgusML Windows support module OK!")
