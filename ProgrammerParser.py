import tkinter as tk
from tkinter import filedialog, ttk, messagebox, scrolledtext
import zipfile
import os
import re
import json
from datetime import datetime
import webbrowser
import io
import threading
import requests
import hashlib
import sys

APP_VERSION = "3.0.1"

ignore_vins = {
    "LB1WA5884A8008781",
    "LSGWS52X27S057878",
    "WP0AA2978BL012976"
}

TAB_KEYS = [
    "Summary", "UserData", "KeyGen", "BatteryInfo", "DataLogging", "EEPROM", "Wifi", "Errors", "About"
]

def is_valid_vin(vin):
    translit = {
        'A':1, 'B':2, 'C':3, 'D':4, 'E':5, 'F':6, 'G':7, 'H':8, 'J':1, 'K':2, 'L':3, 'M':4, 'N':5,
        'P':7, 'R':9, 'S':2, 'T':3, 'U':4, 'V':5, 'W':6, 'X':7, 'Y':8, 'Z':9,
        '0':0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9
    }
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
    vin = vin.upper()
    if len(vin) != 17 or any(c in "IOQ" for c in vin):
        return False
    total = 0
    for i in range(17):
        c = vin[i]
        if c not in translit:
            return False
        value = translit[c]
        total += value * weights[i]
    check_digit = vin[8]
    check_value = total % 11
    if check_value == 10:
        check_value = 'X'
    else:
        check_value = str(check_value)
    return str(check_digit) == str(check_value)

vin_years = {
    **{c: y for c, y in zip("ABCDEFGHJKLMNPRSTVWXY123456789", range(1980, 2010))},
    **{c: y for c, y in zip("ABCDEFGHJKLMNPRSTVWXY123456789", range(2010, 2040))}
}
def get_year_from_vin(vin):
    c = vin[9]
    return vin_years.get(c, "Unknown")

vin_wmi = {
    "1G1": "Chevrolet", "2C3": "Chrysler", "3FA": "Ford", "JHM": "Honda", "1C4": "Chrysler",
    "1HG": "Honda", "1N4": "Nissan", "1FT": "Ford", "5YJ": "Tesla", "1FM": "Ford", "2HG": "Honda",
    "1FZ": "Ford", "JTD": "Toyota", "1J4": "Jeep", "1VW": "Volkswagen", "WAU": "Audi",
}
def get_make_from_vin(vin):
    return vin_wmi.get(vin[:3], "Unknown")

def decode_vin_online(vin, timeout=3):
    url = f"https://vpic.nhtsa.dot.gov/api/vehicles/decodevin/{vin}?format=json"
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
        out = {"year": "Unknown", "make": "Unknown", "model": "Unknown"}
        for item in data.get("Results", []):
            if item["Variable"] == "Model Year" and item["Value"]:
                out["year"] = item["Value"]
            elif item["Variable"] == "Make" and item["Value"]:
                out["make"] = item["Value"]
            elif item["Variable"] == "Model" and item["Value"]:
                out["model"] = item["Value"]
        if out["year"] != "Unknown" and out["make"] != "Unknown":
            return out
    except Exception:
        pass
    return None

def extract_vins_from_log(text, vin_cache=None, offline_only=False, errors=None, remove_dupes=False):
    vin_regex = r"\b([A-HJ-NPR-Z0-9]{17})\b"
    results = []
    if vin_cache is None:
        vin_cache = {}
    if errors is None:
        errors = []
    seen_vins = set()
    for line in text.splitlines():
        vin_match = re.search(vin_regex, line)
        if vin_match:
            vin = vin_match.group(1)
            if vin in ignore_vins:
                continue
            if vin.isdigit() or not is_valid_vin(vin):
                continue
            if remove_dupes and vin in seen_vins:
                continue
            ts_match = re.match(r"(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})", line)
            timestamp = ts_match.group(1) if ts_match else ""
            if vin in vin_cache:
                year, make, model = vin_cache[vin]
            else:
                if not offline_only:
                    data = decode_vin_online(vin)
                else:
                    data = None
                if data:
                    year, make, model = data["year"], data["make"], data["model"]
                else:
                    year = get_year_from_vin(vin)
                    make = get_make_from_vin(vin)
                    model = "Unknown"
                vin_cache[vin] = (year, make, model)
            results.append((timestamp, vin, year, make, model))
            seen_vins.add(vin)
    return results

def is_main_log_file(path):
    return path.lower().endswith('main.log')

def is_zip_file(path):
    return path.lower().endswith('.zip')

def search_main_logs_in_zip(zf, parent_path="", vin_cache=None, offline_only=False, errors=None, remove_dupes=False):
    results = []
    for name in zf.namelist():
        this_path = os.path.join(parent_path, name)
        if is_main_log_file(name):
            with zf.open(name) as f:
                log_text = f.read().decode(errors="ignore")
                vin_entries = extract_vins_from_log(log_text, vin_cache, offline_only, errors, remove_dupes)
                for ts, vin, year, make, model in vin_entries:
                    results.append((this_path, ts, vin, year, make, model))
        elif is_zip_file(name):
            with zf.open(name) as f:
                zip_bytes = io.BytesIO(f.read())
                try:
                    with zipfile.ZipFile(zip_bytes, 'r') as nested_zip:
                        results.extend(search_main_logs_in_zip(nested_zip, parent_path=this_path, vin_cache=vin_cache, offline_only=offline_only, errors=errors, remove_dupes=remove_dupes))
                except Exception as ex:
                    if errors is not None:
                        errors.append(f"Failed to parse nested ZIP {this_path}: {ex}")
    return results

def extract_autel_user_fields(text):
    fields = {}
    for key in ["autelId", "nickname", "phoneNumber", "city", "state"]:
        m = re.search(rf'"{key}"\s*:\s*"([^"]*)"', text)
        fields[key] = m.group(1) if m else "N/A"
    return fields

def extract_sensorsdata_fields(xml_text):
    sp_match = re.search(r'<string name="super_properties">([^<]+)</string>', xml_text)
    product_sn = "N/A"
    if sp_match:
        try:
            sp_json = json.loads(sp_match.group(1).replace('&quot;', '"'))
            product_sn = sp_json.get("ProductSN", "N/A")
        except Exception:
            pass

    app_end_match = re.search(r'<string name="app_end_data">([^<]+)</string>', xml_text)
    title = "N/A"
    if app_end_match:
        try:
            app_end_json = json.loads(app_end_match.group(1).replace('&quot;', '"'))
            title = app_end_json.get("$title", "N/A")
        except Exception:
            pass

    first_day_match = re.search(r'<string name="first_day">([^<]+)</string>', xml_text)
    first_day = first_day_match.group(1) if first_day_match else "N/A"

    return {
        "ProductSN": product_sn,
        "title": title,
        "first_use": first_day
    }

def extract_keygen_data(text):
    entries = []
    for line in text.strip().split(';'):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            keysn = data.get("keysn", "")
            menupath = data.get("menupath", "")
            match = re.match(r'^(.*?\d{4}(?:-\d{4})?)', menupath)
            if match:
                menupath = match.group(1)
            raw_time = data.get("starttime", "")
            pretty_time = "N/A"
            if len(raw_time) == 14:
                try:
                    pretty_time = datetime.strptime(raw_time, "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pretty_time = raw_time
            result = data.get("result", "")
            entries.append({
                "keysn": keysn,
                "menupath": menupath,
                "starttime": pretty_time,
                "result": result
            })
        except Exception:
            continue
    return entries

def extract_batteryinfo_vins(text, remove_dupes=False):
    vins = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.isdigit() and is_valid_vin(line) and line not in ignore_vins:
            if remove_dupes and line in seen:
                continue
            vins.append(line)
            seen.add(line)
    return vins

def extract_eeprom_files(zf, errors=None):
    eeprom_files = []
    for fname in zf.namelist():
        if "CloudEData" in fname and fname.lower().endswith(".json"):
            basename = os.path.basename(fname)
            match = re.match(r"(\d{10,13})[_\.]", basename)
            if match:
                ts_digits = match.group(1)
                if len(ts_digits) == 13:
                    ts_ms = int(ts_digits)
                    ts_str = datetime.utcfromtimestamp(ts_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')
                elif len(ts_digits) == 10:
                    ts_s = int(ts_digits)
                    ts_str = datetime.utcfromtimestamp(ts_s).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    ts_str = "Unknown"
            else:
                try:
                    info = zf.getinfo(fname)
                    ts_dt = datetime(*info.date_time)
                    ts_str = ts_dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    ts_str = "Unknown"
            with zf.open(fname) as jf:
                try:
                    jdata = json.load(jf)
                except Exception as ex:
                    if errors is not None:
                        errors.append(f"Failed to parse EEPROM JSON {fname}: {ex}")
                    continue
            vin = jdata.get("VehicleVIN", "")
            make = jdata.get("VehicleCar", "")
            model = jdata.get("VehicleModel", "")
            year = jdata.get("VehicleYear", "")
            eeprom_files.append({
                "timestamp": ts_str,
                "vin": vin,
                "make": make,
                "model": model,
                "year": year
            })
    return eeprom_files

def extract_wifi_networks(zf, errors=None):
    wifi_file = [
        f for f in zf.namelist()
        if f.lower().endswith("data/misc/wifi/wificonfigstore.xml")
    ]
    networks = []
    if wifi_file:
        with zf.open(wifi_file[0]) as wf:
            xml = wf.read().decode(errors="ignore")
            for net_xml in re.findall(r'<WifiConfiguration>(.*?)</WifiConfiguration>', xml, flags=re.DOTALL):
                ssid = re.search(r'<string name="SSID">&quot;(.*?)&quot;</string>', net_xml)
                psk = re.search(r'<string name="PreSharedKey">&quot;(.*?)&quot;</string>', net_xml)
                ctime = re.search(r'<string name="CreationTime">time=(.*?)</string>', net_xml)
                networks.append({
                    "ssid": ssid.group(1) if ssid else "",
                    "psk": psk.group(1) if psk else "",
                    "ctime": ctime.group(1) if ctime else "",
                })
    return networks

def hash_file(filepath, md5=True, sha1=True, sha256=True):
    hashes = {}
    if md5: hashes['MD5'] = hashlib.md5()
    if sha1: hashes['SHA1'] = hashlib.sha1()
    if sha256: hashes['SHA256'] = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}

class OptionsDialog(tk.Toplevel):
    def __init__(self, master, settings):
        super().__init__(master)
        self.title("Options")
        self.resizable(False, False)
        self.settings = settings
        self.grab_set()
        self.transient(master)
        self.configure(bg="#222")

        # Hashes
        tk.Label(self, text="Hash Algorithms:", bg="#222", fg="#fff", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky='w', padx=10, pady=(10,0))
        self.md5_var = tk.BooleanVar(value=settings['md5'])
        self.sha1_var = tk.BooleanVar(value=settings['sha1'])
        self.sha256_var = tk.BooleanVar(value=settings['sha256'])
        self.md5_chk = tk.Checkbutton(self, text="MD5", variable=self.md5_var, bg="#222", fg="#fff", selectcolor="#444", activebackground="#333")
        self.sha1_chk = tk.Checkbutton(self, text="SHA1", variable=self.sha1_var, bg="#222", fg="#fff", selectcolor="#444", activebackground="#333")
        self.sha256_chk = tk.Checkbutton(self, text="SHA256", variable=self.sha256_var, bg="#222", fg="#fff", selectcolor="#444", activebackground="#333")
        self.md5_chk.grid(row=1, column=0, sticky='w', padx=22)
        self.sha1_chk.grid(row=1, column=1, sticky='w', padx=10)
        self.sha256_chk.grid(row=1, column=2, sticky='w', padx=10)

        # Dedupe
        tk.Label(self, text="VIN Extraction:", bg="#222", fg="#fff", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky='w', padx=10, pady=(12,0))
        self.dedupe_var = tk.BooleanVar(value=settings['dedupe'])
        self.dedupe_chk = tk.Checkbutton(self, text="Remove Duplicate VINs", variable=self.dedupe_var, bg="#222", fg="#fff", selectcolor="#444", activebackground="#333")
        self.dedupe_chk.grid(row=3, column=0, sticky='w', padx=22, pady=(0,0), columnspan=3)

        # Report sections
        tk.Label(self, text="Include Sections:", bg="#222", fg="#fff", font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky='w', padx=10, pady=(12,0))
        self.tabs_vars = {}
        row = 5
        for i, k in enumerate(TAB_KEYS):
            var = tk.BooleanVar(value=settings['tabs'][k])
            self.tabs_vars[k] = var
            chk = tk.Checkbutton(self, text=k, variable=var, bg="#222", fg="#fff", selectcolor="#444", activebackground="#333")
            chk.grid(row=row, column=i%3, sticky='w', padx=22, pady=(0,0))
            if i%3==2:
                row += 1

        # Save/cancel
        btn_frame = tk.Frame(self, bg="#222")
        btn_frame.grid(row=row+1, column=0, columnspan=3, pady=14)
        tk.Button(btn_frame, text="OK", width=10, command=self.save_options).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Cancel", width=10, command=self.destroy).pack(side='left', padx=10)

    def save_options(self):
        self.settings['md5'] = self.md5_var.get()
        self.settings['sha1'] = self.sha1_var.get()
        self.settings['sha256'] = self.sha256_var.get()
        self.settings['dedupe'] = self.dedupe_var.get()
        for k, var in self.tabs_vars.items():
            self.settings['tabs'][k] = var.get()
        self.destroy()

class ProgrammerParserApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Programmer Parser {APP_VERSION}")
        self.root.configure(bg="#18191c")
        self.root.geometry("900x670")
        self.root.minsize(750, 570)
        self.root.resizable(True, True)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background="#18191c", foreground="#e6e6e6", font=("Segoe UI", 10))
        style.configure('TButton', background="#39597e", foreground="#e6e6e6", font=("Segoe UI", 11), borderwidth=0)
        style.map('TButton', background=[('active', '#46688f'), ('pressed', '#39597e')])
        style.configure('TEntry', foreground="#e6e6e6", fieldbackground="#24262b", bordercolor="#292b2f", borderwidth=2, font=("Segoe UI", 10))
        style.configure("Horizontal.TProgressbar", background="#39597e", troughcolor="#24262b", bordercolor="#18191c")

        # Defaults/settings
        self.settings = {
            "md5": True, "sha1": False, "sha256": False,
            "dedupe": False,
            "tabs": {k: True for k in TAB_KEYS}
        }
        # Main frame
        self.frame = tk.Frame(self.root, bg="#18191c")
        self.frame.pack(fill='both', expand=True, padx=8, pady=8)

        # File/folder selectors
        ttk.Label(self.frame, text="Select Extraction ZIP:").grid(row=0, column=0, sticky='w', pady=(0,5))
        self.zip_var = tk.StringVar()
        self.zip_entry = ttk.Entry(self.frame, textvariable=self.zip_var, width=60)
        self.zip_entry.grid(row=0, column=1, sticky='ew', pady=(0,5))
        self.zip_btn = ttk.Button(self.frame, text="Browse", command=self.browse_zip)
        self.zip_btn.grid(row=0, column=2, padx=(6,0), pady=(0,5))

        ttk.Label(self.frame, text="Report Location:").grid(row=1, column=0, sticky='w', pady=(0,5))
        self.report_var = tk.StringVar(value=os.path.dirname(sys.argv[0]) or os.getcwd())
        self.report_entry = ttk.Entry(self.frame, textvariable=self.report_var, width=60)
        self.report_entry.grid(row=1, column=1, sticky='ew', pady=(0,5))
        self.rep_btn = ttk.Button(self.frame, text="Browse", command=self.browse_report)
        self.rep_btn.grid(row=1, column=2, padx=(6,0), pady=(0,5))

        # --- Case/Notes/Options row ---
        ttk.Label(self.frame, text="Case Number:").grid(row=2, column=0, sticky='w', pady=(0,5))
        self.case_var = tk.StringVar()
        self.case_entry = ttk.Entry(self.frame, textvariable=self.case_var, width=30)
        self.case_entry.grid(row=2, column=1, sticky='w', pady=(0,5))

        self.options_btn = ttk.Button(self.frame, text="Options", command=self.open_options)
        self.options_btn.grid(row=2, column=2, padx=(6,0), pady=(0,5))

        # Notes
        ttk.Label(self.frame, text="Investigator Notes:").grid(row=3, column=0, sticky='nw')
        self.notes_text = scrolledtext.ScrolledText(self.frame, height=3, width=55, wrap='word')
        self.notes_text.grid(row=3, column=1, sticky='ew', pady=(0,5))

        # Progress bar and status
        self.progress = ttk.Progressbar(self.frame, orient="horizontal", length=720, mode="determinate")
        self.progress.grid(row=4, column=0, columnspan=3, sticky='ew', pady=(5,0))
        self.status_var = tk.StringVar(value="")
        status_label = ttk.Label(self.frame, textvariable=self.status_var, font=("Segoe UI", 9, "italic"))
        status_label.grid(row=5, column=0, columnspan=3, sticky='w')

        # Process/Cancel and log
        self.proc_btn = ttk.Button(self.frame, text="Process Extraction", command=self.process_or_cancel)
        self.proc_btn.grid(row=6, column=0, columnspan=2, sticky='ew', pady=(7,0))
        self.copy_errors_btn = ttk.Button(self.frame, text="Copy Log", command=self.copy_errors)
        self.copy_errors_btn.grid(row=6, column=2, sticky='ew', padx=(6,0), pady=(7,0))

        # Log Box (expandable)
        ttk.Label(self.frame, text="Status Log:").grid(row=7, column=0, columnspan=3, sticky='w', pady=(9,0))
        self.log_box = scrolledtext.ScrolledText(self.frame, bg="#232323", fg="#e6e6e6", font=("Consolas", 10), height=12, borderwidth=0, highlightthickness=0, wrap="word")
        self.log_box.grid(row=8, column=0, columnspan=3, sticky='nsew', pady=(0,6))
        self.frame.grid_columnconfigure(1, weight=1)
        self.frame.grid_rowconfigure(8, weight=1)

        footer = tk.Label(self.frame, text=f"Developed by: CodyPelkey", fg="#bcbcbc", bg="#18191c", anchor="w", font=("Segoe UI", 9))
        footer.grid(row=9, column=0, columnspan=3, sticky='w', pady=(6,0))

        self.cancel_requested = False

    def browse_zip(self):
        path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if path:
            self.zip_var.set(path)

    def browse_report(self):
        path = filedialog.askdirectory()
        if path:
            self.report_var.set(path)

    def open_options(self):
        dlg = OptionsDialog(self.root, self.settings.copy())
        self.root.wait_window(dlg)
        # Save changes from dialog
        self.settings.update(dlg.settings)

    def set_controls_enabled(self, enabled=True):
        state = "normal" if enabled else "disabled"
        self.zip_btn.config(state=state)
        self.rep_btn.config(state=state)
        self.options_btn.config(state=state)
        self.case_entry.config(state=state)
        self.notes_text.config(state=state)

    def log(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{ts}] {message}\n")
        self.log_box.see(tk.END)
        self.root.update()

    def copy_errors(self):
        all_log = self.log_box.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(all_log)
        messagebox.showinfo("Copied", "Log (including errors) copied to clipboard.")

    def process_or_cancel(self):
        if self.proc_btn.cget('text') == "Process Extraction":
            self.process_extraction()
        else:
            self.cancel_requested = True
            self.status_var.set("Cancelling...")

    def process_extraction(self):
        self.cancel_requested = False
        self.set_controls_enabled(False)
        self.proc_btn.config(text="Cancel", state="normal")
        self.status_var.set("Processing, please wait...")
        self.log_box.delete(1.0, tk.END)
        self.progress['value'] = 0
        self.root.update()
        threading.Thread(target=self._process_extraction_thread, daemon=True).start()

    def _process_extraction_thread(self):
        zip_path = self.zip_var.get()
        out_dir = self.report_var.get()
        case_number = self.case_var.get().strip()
        notes = self.notes_text.get("1.0", tk.END).strip()
        hashes = {}

        def finish():
            self.set_controls_enabled(True)
            self.proc_btn.config(text="Process Extraction", state="normal")

        if not zip_path.lower().endswith(".zip"):
            self.root.after(0, lambda: self.log("Error: Please select a valid ZIP file."))
            self.root.after(0, lambda: messagebox.showerror("Invalid ZIP", "Please select a valid ZIP file."))
            self.root.after(0, finish)
            return
        if not os.path.isfile(zip_path):
            self.root.after(0, lambda: self.log("Error: ZIP file not found."))
            self.root.after(0, lambda: messagebox.showerror("Missing File", "ZIP file not found."))
            self.root.after(0, finish)
            return
        if not os.path.isdir(out_dir):
            self.root.after(0, lambda: self.log("Error: Output folder not found."))
            self.root.after(0, lambda: messagebox.showerror("Missing Folder", "Please select a valid report folder."))
            self.root.after(0, finish)
            return

        self.root.after(0, lambda: self.log("Starting file hash calculation..."))
        hashes = hash_file(
            zip_path,
            md5=self.settings['md5'],
            sha1=self.settings['sha1'],
            sha256=self.settings['sha256']
        )
        self.root.after(0, lambda: self.log("File hashes: " + "  ".join([f"{k}: {v}" for k, v in hashes.items()])))

        try:
            errors = []
            self.root.after(0, lambda: self.log("Opening ZIP file..."))
            with zipfile.ZipFile(zip_path, 'r') as zf:
                if self.cancel_requested: self.root.after(0, finish); return
                self.root.after(0, lambda: self.log("Detecting programmer type..."))
                build_prop_path = [f for f in zf.namelist() if f.lower().endswith('system/build.prop')]
                programmer_type = None
                if build_prop_path:
                    with zf.open(build_prop_path[0]) as bp:
                        content = bp.read().decode(errors="ignore")
                        if "ro.product.model=sm2031" in content:
                            programmer_type = "Autel"
                            self.root.after(0, lambda: self.log("Autel programmer detected."))
                        else:
                            self.root.after(0, lambda: self.log("Not an Autel Programmer."))
                else:
                    self.root.after(0, lambda: self.log("Unable to determine programmer type."))

                user_fields = {}
                if programmer_type == "Autel":
                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Looking for User Data files..."))
                    user_center_path = [f for f in zf.namelist() if f.lower().endswith('data/data/com.autel.base.usercenter/files/mmkv/usercenter')]
                    if user_center_path:
                        self.root.after(0, lambda: self.log(f"User Data found. Extracting..."))
                        with zf.open(user_center_path[0]) as uf:
                            user_content = uf.read().decode(errors="ignore")
                            user_fields = extract_autel_user_fields(user_content)
                        self.root.after(0, lambda: self.log("Extracted user data information."))
                    else:
                        self.root.after(0, lambda: self.log("User Data file not found."))
                        errors.append("User Data file not found for Autel programmer.")

                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Looking for Device Info..."))
                    sensors_file = [f for f in zf.namelist() if f.lower().endswith('data/data/com.autel.maxiap200.bs200/shared_prefs/com.sensorsdata.analytics.android.sdk.sensorsdataapi.xml')]
                    sensors_data = {}
                    if sensors_file:
                        self.root.after(0, lambda: self.log(f"Device Info data found. Extracting..."))
                        with zf.open(sensors_file[0]) as sf:
                            sensors_content = sf.read().decode(errors="ignore")
                            sensors_data = extract_sensorsdata_fields(sensors_content)
                        self.root.after(0, lambda: self.log("Extracted Device Info."))
                    else:
                        self.root.after(0, lambda: self.log("Device Info file not found."))
                        errors.append("Device Info file not found.")

                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Looking for Universal Key Generation file..."))
                    keygen_file = [f for f in zf.namelist() if f.lower().endswith('data/data/com.autel.maxiap200.bs200/files/0001010b.ini')]
                    keygen_data = []
                    if keygen_file:
                        self.root.after(0, lambda: self.log(f"keygen file found. Extracting..."))
                        with zf.open(keygen_file[0]) as kf:
                            keygen_content = kf.read().decode(errors="ignore")
                            keygen_data = extract_keygen_data(keygen_content)
                        self.root.after(0, lambda: self.log(f"Extracted {len(keygen_data)} keygen records."))
                    else:
                        self.root.after(0, lambda: self.log("Universal Key Generation Data file not found."))
                        errors.append("Universal Key Generation Data file not found.")

                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Looking for BatteryInfo1 VIN file..."))
                    batteryinfo_file = [f for f in zf.namelist() if f.lower().endswith('data/media/0/maxiapscan/vehiclekt/keytooldiag/en_batteryinfo_1.txt')]
                    batteryinfo_vins = []
                    if batteryinfo_file:
                        self.root.after(0, lambda: self.log(f"BatteryInfo1 file found. Extracting..."))
                        with zf.open(batteryinfo_file[0]) as bf:
                            batteryinfo_content = bf.read().decode(errors="ignore")
                            batteryinfo_vins = extract_batteryinfo_vins(batteryinfo_content, remove_dupes=self.settings['dedupe'])
                        self.root.after(0, lambda: self.log(f"Extracted {len(batteryinfo_vins)} VINs from BatteryInfo1."))
                    else:
                        self.root.after(0, lambda: self.log("BatteryInfo1 file not found."))
                        errors.append("BatteryInfo1 file not found.")

                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Searching through DataLogs for VINs..."))
                    datalogging_entries = []
                    vin_cache = {}
                    online_failed = False
                    try:
                        for f in zf.namelist():
                            if 'datalogging/' in f.lower():
                                if is_zip_file(f):
                                    with zf.open(f) as inner_zip:
                                        inner_bytes = io.BytesIO(inner_zip.read())
                                        try:
                                            with zipfile.ZipFile(inner_bytes, 'r') as nested_zip:
                                                datalogging_entries.extend(
                                                    search_main_logs_in_zip(nested_zip, parent_path=f, vin_cache=vin_cache, offline_only=False, errors=errors, remove_dupes=self.settings['dedupe'])
                                                )
                                        except Exception as ex:
                                            errors.append(f"Failed to parse nested ZIP {f}: {ex}")
                                elif is_main_log_file(f):
                                    with zf.open(f) as lf:
                                        log_text = lf.read().decode(errors="ignore")
                                        vin_entries = extract_vins_from_log(
                                            log_text, vin_cache, offline_only=False, errors=errors, remove_dupes=self.settings['dedupe']
                                        )
                                        for ts, vin, year, make, model in vin_entries:
                                            datalogging_entries.append((f, ts, vin, year, make, model))
                    except Exception as e:
                        online_failed = True
                        errors.append(f"Online VIN lookup failed: {e}")

                    if self.cancel_requested: self.root.after(0, finish); return
                    if online_failed or not datalogging_entries:
                        self.root.after(0, lambda: self.log("Falling back to offline VIN decoding for DataLogs..."))
                        datalogging_entries = []
                        vin_cache = {}
                        for f in zf.namelist():
                            if 'datalogging/' in f.lower():
                                if is_zip_file(f):
                                    with zf.open(f) as inner_zip:
                                        inner_bytes = io.BytesIO(inner_zip.read())
                                        try:
                                            with zipfile.ZipFile(inner_bytes, 'r') as nested_zip:
                                                datalogging_entries.extend(
                                                    search_main_logs_in_zip(nested_zip, parent_path=f, vin_cache=vin_cache, offline_only=True, errors=errors, remove_dupes=self.settings['dedupe'])
                                                )
                                        except Exception as ex:
                                            errors.append(f"Failed to parse nested ZIP {f}: {ex}")
                                elif is_main_log_file(f):
                                    with zf.open(f) as lf:
                                        log_text = lf.read().decode(errors="ignore")
                                        vin_entries = extract_vins_from_log(
                                            log_text, vin_cache, offline_only=True, errors=errors, remove_dupes=self.settings['dedupe']
                                        )
                                        for ts, vin, year, make, model in vin_entries:
                                            datalogging_entries.append((f, ts, vin, year, make, model))
                    self.root.after(0, lambda: self.log(f"DataLogs: {len(datalogging_entries)} VINs found and extracted."))

                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Looking for EEPROM files..."))
                    eeprom_files = extract_eeprom_files(zf, errors=errors)
                    self.root.after(0, lambda: self.log(f"EEPROM Files found: {len(eeprom_files)}"))

                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Looking for saved WiFi networks..."))
                    wifi_networks = extract_wifi_networks(zf, errors=errors)
                    self.root.after(0, lambda: self.log(f"Saved Wifi Networks found: {len(wifi_networks)}"))

                    if self.cancel_requested: self.root.after(0, finish); return
                    self.root.after(0, lambda: self.log("Building HTML report..."))

                    data = {
                        "Programmer": programmer_type,
                        "user_fields": user_fields, 
                        **sensors_data,
                        "keygen_data": keygen_data,
                        "batteryinfo_vins": batteryinfo_vins,
                        "datalogging_entries": datalogging_entries,
                        "eeprom_files": eeprom_files,
                        "wifi_networks": wifi_networks,
                        "errors": errors,
                        "hashes": hashes,
                        "case_number": case_number,
                        "notes": notes,
                        "zip_file": os.path.basename(zip_path)
                    }
                    self.root.after(0, lambda: self.generate_html_report(out_dir, zip_path, data))
                    self.root.after(0, lambda: self.progress.config(value=100))
                    self.root.after(0, lambda: self.status_var.set("Done!"))
                    self.root.after(0, lambda: self.log("Report generated successfully."))
                else:
                    self.root.after(0, lambda: self.log("Not an Autel programmer, or required files not found."))
        except Exception as e:
            self.root.after(0, lambda: self.log(f"Error: {e}"))
            self.root.after(0, lambda: messagebox.showerror("Processing Error", str(e)))
        finally:
            self.root.after(0, finish)

    def generate_html_report(self, out_dir, zip_path, data):
        now = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        filename = f"ProgrammerParser_Autel_{now}.html"
        out_file = os.path.join(out_dir, filename)
        display_date = datetime.now().strftime("%B %d, %Y %H:%M:%S")
        hashes = data.get("hashes", {})

        def include(tab, html):
            return self.settings['tabs'][tab] and html or ""

        summary_tab = f"""<div id="summary" class="tab-content active">
        <h2>Report Summary</h2>
        <div class="info-card">
            <ul class="info-list">
            <li><b>Case Number:</b> {data.get('case_number','')}</li>
            <li><b>Investigator Notes:</b> {data.get('notes','')}</li>
            <li><b>Report file:</b> {filename}</li>
            <li><b>Extraction ZIP:</b> {data.get('zip_file','')}</li>
            <li><b>Date:</b> {display_date}</li>
            <li><b>Device:</b> {data.get('ProductSN', 'N/A')}</li>
            <li><b>VINs found (all):</b> {len(data.get('batteryinfo_vins',[])) + len(data.get('datalogging_entries',[]))}</li>
            <li><b>EEPROM records:</b> {len(data.get('eeprom_files',[]))}</li>
            <li><b>Saved WiFi networks:</b> {len(data.get('wifi_networks',[]))}</li>
            {''.join([f"<li><b>ZIP {k}:</b> {v}</li>" for k, v in hashes.items()])}
            </ul>
        </div>
        </div>"""

        user_fields = data.get("user_fields", {})

        user_tab = f"""<div id="userdata" class="tab-content">
        <h2>User Data</h2>
        {"<div class='empty-msg'>No user data found.</div>" if not user_fields else ""}
        <div class="info-card">
        <ul class="info-list">
            <li><b>User ID:</b> {user_fields.get('autelId', 'N/A')}</li>
            <li><b>Nickname:</b> {user_fields.get('nickname', 'N/A')}</li>
            <li><b>Phone Number:</b> {user_fields.get('phoneNumber', 'N/A')}</li>
            <li><b>City:</b> {user_fields.get('city', 'N/A')}</li>
            <li><b>State:</b> {user_fields.get('state', 'N/A')}</li>
        </ul>
        </div>
        </div>"""

        keygen_tab = f"""<div id="keygen" class="tab-content">
        <h2>Universal Key Generation Data</h2>
        {"<div class='empty-msg'>No key generation data found.</div>" if not data.get('keygen_data') else ""}
        <table>
            <tr><th>Key Serial</th><th>Vehicle</th><th>Start Time</th><th>Result</th></tr>
            {''.join([
                f"<tr><td>{entry['keysn']}</td><td>{entry['menupath']}</td><td>{entry['starttime']}</td><td>{entry['result']}</td></tr>"
                for entry in data.get('keygen_data', [])
            ])}
        </table>
        </div>"""

        batteryinfo_tab = f"""<div id="batteryinfo" class="tab-content">
        <h2>BatteryInfo1 VINs</h2>
        {"<div class='empty-msg'>No BatteryInfo1 VINs found.</div>" if not data.get('batteryinfo_vins') else ""}
        <table>
            <tr><th>VIN</th></tr>
            {''.join([f"<tr><td>{vin}</td></tr>" for vin in data.get('batteryinfo_vins', [])])}
        </table>
        </div>"""

        datalogging_tab = f"""<div id="datalogging" class="tab-content">
        <h2>DataLogging VINs</h2>
        {"<div class='empty-msg'>No DataLogging VINs found.</div>" if not data.get('datalogging_entries') else ""}
        <table>
            <tr><th>File Path</th><th>Timestamp</th><th>VIN</th><th>Year</th><th>Make</th><th>Model</th></tr>
            {''.join([
                f"<tr><td class='filepath'>{entry[0]}</td><td>{entry[1]}</td><td>{entry[2]}</td><td>{entry[3]}</td><td>{entry[4]}</td><td>{entry[5]}</td></tr>"
                for entry in data.get('datalogging_entries', [])
            ])}
        </table>
        </div>"""

        eeprom_tab = f"""<div id="eeprom" class="tab-content">
        <h2>EEPROM Files</h2>
        {"<div class='empty-msg'>No EEPROM files found.</div>" if not data.get('eeprom_files') else ""}
        <table>
            <tr><th>Timestamp</th><th>Year</th><th>Make</th><th>Model</th><th>VIN</th></tr>
            {''.join([
                f"<tr><td>{e['timestamp']}</td><td>{e['year']}</td><td>{e['make']}</td><td>{e['model']}</td><td>{e['vin']}</td></tr>"
                for e in data.get('eeprom_files', [])
            ])}
        </table>
        </div>"""

        wifi_tab = f"""<div id="wifi" class="tab-content">
        <h2>Saved Wifi Networks</h2>
        {"<div class='empty-msg'>No Wifi networks found.</div>" if not data.get('wifi_networks') else ""}
        <table>
            <tr><th>SSID</th><th>Password</th><th>Created</th></tr>
            {''.join([
                f"<tr><td>{net['ssid']}</td><td>{net['psk']}</td><td>{net['ctime']}</td></tr>"
                for net in data.get('wifi_networks', [])
            ])}
        </table>
        </div>"""

        errors_tab = f"""<div id="errors" class="tab-content">
        <h2>Errors/Warnings</h2>
        {"<div class='empty-msg'>No errors encountered.</div>" if not data.get('errors') else ""}
        <ul class="info-list">
            {''.join([f"<li>{err}</li>" for err in data.get('errors', [])])}
        </ul>
        </div>"""

        about_tab = f"""<div id="about" class="tab-content">
        <h2>About</h2>
        <div class="info-card">
            <b>ProgrammerParser Autel Report</b><br>
            Generated at: {display_date}<br>
            Developed by Cody Pelkey<br>
            <br>
            <a href='https://github.com/CodyPelkey' style="color:#7bcfff;" target="_blank">GitHub</a>
        </div>
        </div>"""

        tab_titles = [k for k in TAB_KEYS if self.settings['tabs'][k]]
        tab_divs = "".join([
            f'<div class="tab{" active" if i == 0 else ""}" onclick="showTab(\'{tab.lower()}\')">{tab}</div>'
            for i, tab in enumerate(tab_titles)
        ])

        html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>ProgrammerParser Autel Report</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
    body {{
        background: #181c20;
        color: #f3f3f3;
        font-family: 'Segoe UI', Arial, sans-serif;
        margin: 0;
        padding: 0;
    }}
    .header {{
        background: linear-gradient(90deg, #39597e 0%, #4fa3f7 100%);
        color: #fff;
        padding: 28px 0 16px 0;
        text-align: center;
        letter-spacing: 1px;
        border-bottom-left-radius: 36px 18px;
        border-bottom-right-radius: 36px 18px;
    }}
    h1 {{
        margin: 0 0 12px 0;
        font-size: 2.5em;
        letter-spacing: 1.5px;
        font-weight: 700;
    }}
    h2 {{
        color: #7bcfff;
        font-size: 1.6em;
        border-bottom: 1px solid #39597e;
        padding-bottom: 6px;
        margin-bottom: 18px;
    }}
    .tabs {{
        display: flex;
        border-bottom: 2px solid #444;
        margin-top: 40px;
        flex-wrap: wrap;
    }}
    .tab {{
        padding: 12px 36px;
        margin-right: 8px;
        background: #232323;
        border-top-left-radius: 10px;
        border-top-right-radius: 10px;
        cursor: pointer;
        color: #bbb;
        font-weight: 600;
        font-size: 1.1em;
        transition: background 0.2s;
        border-bottom: none;
        box-shadow: 0 2px 6px #1a1d20a6;
        margin-bottom: 0;
    }}
    .tab.active, .tab:hover {{
        background: #39597e;
        color: #fff;
    }}
    .tab-content {{
        display: none;
        padding: 36px 28px 32px 28px;
        background: #232323;
        border-radius: 0 0 18px 18px;
        font-size: 1.1em;
        box-shadow: 0 4px 24px #21273199;
    }}
    .tab-content.active {{
        display: block;
    }}
    .info-card {{
        background: #20242c;
        border-radius: 10px;
        padding: 28px 32px 18px 32px;
        box-shadow: 0 2px 16px #28303a66;
        margin-bottom: 10px;
        width: 100%;
        max-width: 900px;
    }}
    .info-list {{
        list-style: none;
        padding: 0;
        margin: 0;
    }}
    .info-list li {{
        padding: 10px 0;
        border-bottom: 1px solid #31363c;
        margin-bottom: 2px;
        font-size: 1.15em;
    }}
    .info-list li:last-child {{
        border-bottom: none;
    }}
    .footer {{
        margin-top: 36px;
        color: #a0adc0;
        font-size: 0.98em;
        text-align: center;
        opacity: 0.75;
        padding-bottom: 24px;
    }}
    .empty-msg {{
        color: #cfcfcf;
        background: #2b2e33;
        border-radius: 7px;
        padding: 22px;
        text-align: center;
        margin: 0 0 18px 0;
        font-size: 1.11em;
        font-style: italic;
    }}
    @media (max-width:900px) {{
        .info-card {{ max-width: 97vw; padding: 14px 4vw 8px 4vw; }}
        .tab-content {{ padding: 12px 2vw 18px 2vw; }}
        h1 {{ font-size: 1.3em; }}
        table {{ font-size: 1em; }}
    }}
    table, th, td {{ border: 1px solid #28303a; }}
    th {{
        color: #fff;
        font-weight:700;
        padding: 12px 16px;
        background: #39597e;
        font-size: 1.10em;
        text-align: center;
    }}
    td {{
        padding: 12px 16px;
        font-size: 1.09em;
        text-align: left;
        background: #23292f;
        vertical-align: middle;
        line-height: 1.35em;
        word-break: break-word;
    }}
    tr:nth-child(even) td {{
        background: #212731;
    }}
    tr:hover td {{
        background: #334059;
    }}
    td.filepath {{
        word-break: break-all;
        max-width: 320px;
        white-space: pre-wrap;
    }}
    </style>
    </head>
    <body>
    <div class="header">
    <h1>ProgrammerParser Autel Report</h1>
    <div style="font-size:1.1em;">Generated at: {display_date}</div>
    </div>
    <div class="tabs">
    {tab_divs}
    </div>
    {include('Summary', summary_tab)}
    {include('UserData', user_tab)}
    {include('KeyGen', keygen_tab)}
    {include('BatteryInfo', batteryinfo_tab)}
    {include('DataLogging', datalogging_tab)}
    {include('EEPROM', eeprom_tab)}
    {include('Wifi', wifi_tab)}
    {include('Errors', errors_tab)}
    {include('About', about_tab)}
    <div class="footer">
    Report generated by <b>ProgrammerParser</b> &mdash; {display_date}
    </div>
    <script>
    function showTab(tab) {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
    document.querySelector('.tab[onclick*="'+tab+'"]').classList.add('active');
    document.getElementById(tab).classList.add('active');
    }}
    </script>
    </body>
    </html>"""

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html)
        self.log(f"HTML report saved to: {out_file}")
        webbrowser.open(f'file://{os.path.abspath(out_file)}')

if __name__ == "__main__":
    root = tk.Tk()
    app = ProgrammerParserApp(root)
    root.mainloop()
