#!/usr/bin/env python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#           PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF SPACE CRAFT
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import tkinter as tk
import subprocess
import threading
import queue
import socket
import json
import sys
import os

from pathlib import Path
from datetime import datetime
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, messagebox, filedialog

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Define application variables
# Modified: N/A
# -------------------------------------------------------------------------------------

DEFAULTS = {
    "host": "127.0.0.1",
    "port": 0,
    "port2": 0,
    "spacecraft_id": 0,
    "virtual_channel_id": 0,
    "apid": 0,
    "packet_count": 0,
    "tc_packet_count": 0,
    "payload": b"PAYLOAD",
}

separator = "=" * 100

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create functional subroutines called from class.
# Modified: N/A
# -------------------------------------------------------------------------------------

def generate_space_packet(apid: int, packet_count: int, payload: bytes):
    if not 0 <= apid <= 0x7FF:
        raise ValueError("APID must fit in 11 bits (0–2047).")
    if not 0 <= packet_count <= 0x3FFF:
        raise ValueError("Packet count must fit in 14 bits (0–16383).")
    if not payload:
        raise ValueError("CCSDS packet data field cannot be empty.")
    packet_id = (1 << 12) | apid
    sequence_control = (0b11 << 14) | packet_count
    packet_data_length = len(payload) - 1
    if packet_data_length > 0xFFFF:
        raise ValueError("Payload is too large for CCSDS packet data length.")
    return (packet_id.to_bytes(2, "big") + sequence_control.to_bytes(2, "big") + packet_data_length.to_bytes(2, "big") + payload)

def generate_tc_frame(spacecraft_id: int, virtual_channel_id: int,tc_packet_count: int, payload: bytes):
    if not 0 <= spacecraft_id <= 0x3FF:
        raise ValueError("Spacecraft ID must fit in 10 bits (0–1023).")
    if not 0 <= virtual_channel_id <= 0x3F:
        raise ValueError("Virtual channel ID must fit in 6 bits (0–63).")
    if not 0 <= tc_packet_count <= 0xFF:
        raise ValueError("TC frame sequence must fit in 8 bits (0–255).")
    if not payload:
        raise ValueError("Transfer frame data field cannot be empty.")
    total_length = 5 + len(payload) + 2
    if total_length > 1024:
        raise ValueError("TC transfer frame cannot exceed 1024 octets.")
    frame_length = total_length - 1
    header = bytes([(spacecraft_id >> 8) & 0x03,spacecraft_id & 0xFF,(virtual_channel_id << 2) | ((frame_length >> 8) & 0x03),frame_length & 0xFF,tc_packet_count,])
    without_fecf = header + payload
    return without_fecf + ccsds_fecf(without_fecf).to_bytes(2, "big")

def ccsds_fecf(data: bytes):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Create class gui and loop.
# Modified: N/A
# -------------------------------------------------------------------------------------

class SpacecraftGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CCSDS Spacecraft Console — GUI")
        self.geometry("1220x760")
        self.minsize(980, 620)
        self.configure(padx=12, pady=12)
        self.vars = {}
        self.log_queue = queue.Queue()
        self._build_ui()
        self._load_defaults()
        self.status.set("Ready")
        self.after(100, self._drain_log_queue)

    def _build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="CCSDS SPACECRAFT CONSOLE",font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(header, text="The Consultative Committee for Space Data Systems",font=("Segoe UI", 12)).pack(anchor="w", pady=(2, 0))
        warning = ttk.Label(self,text="LAB TARGETS ONLY: live operations may send commands or read target data; always verify host and port first.",foreground="#9a3412")
        warning.pack(anchor="w", pady=(0, 10))

        workspace = ttk.Panedwindow(self, orient="vertical")
        workspace.pack(fill="both", expand=True)
        main = ttk.Panedwindow(workspace, orient="horizontal")
        workspace.add(main, weight=4)
        left = ttk.Frame(main, padding=(0, 0, 10, 0))
        right = ttk.Frame(main)
        main.add(left, weight=1)
        main.add(right, weight=2)
        params = ttk.LabelFrame(left, text="Mission parameters", padding=10)
        params.pack(fill="x")
        ttk.Label(params, text="Target endpoint (IP:PORT)").grid(row=0, column=0, sticky="w", pady=4)
        self.endpoint_var = tk.StringVar()
        endpoint_entry = ttk.Entry(params, textvariable=self.endpoint_var, width=22)
        endpoint_entry.grid(row=0, column=1, sticky="ew", padx=(8, 4), pady=4)
        ttk.Button(params, text="Split", command=self.apply_endpoint).grid(row=0, column=2, sticky="ew", padx=(0, 0), pady=4)
        endpoint_entry.bind("<Return>", lambda _event: self.apply_endpoint())
        fields = [
            ("host", "Target IP / hostname"),
            ("port", "Target TCP port (1–65535)"),
            ("port2", "Listening TCP port (0 = disabled)"),
            ("spacecraft_id", "Spacecraft ID (0–1023)"),
            ("virtual_channel_id", "Virtual channel ID (0–63)"),
            ("apid", "APID (0–2047)"),
            ("packet_count", "Space packet sequence (0–16383)"),
            ("tc_packet_count", "TC frame sequence (0–255)"),]
        for row, (key, label) in enumerate(fields, start=1):
            ttk.Label(params, text=label).grid(row=row, column=0, sticky="w", pady=4)
            var = tk.StringVar()
            self.vars[key] = var
            ttk.Entry(params, textvariable=var, width=22).grid(row=row, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=4)
        params.columnconfigure(1, weight=1)
        left_detail_panes = ttk.Panedwindow(left, orient="vertical")
        left_detail_panes.pack(fill="both", expand=True, pady=(10, 0))
        content_panes = ttk.Panedwindow(left_detail_panes, orient="horizontal")
        left_detail_panes.add(content_panes, weight=3)
        payload_frame = ttk.LabelFrame(content_panes, text="Payload", padding=10)
        content_panes.add(payload_frame, weight=1)
        self.payload_mode = tk.StringVar(value="text")
        mode_row = ttk.Frame(payload_frame)
        mode_row.pack(fill="x", pady=(0, 6))
        ttk.Radiobutton(mode_row, text="Text / ASCII", variable=self.payload_mode,value="text").pack(side="left")
        ttk.Radiobutton(mode_row, text="Hex bytes", variable=self.payload_mode,value="hex").pack(side="left", padx=(12, 0))
        self.payload_text = ScrolledText(payload_frame, height=5, wrap="word")
        self.payload_text.pack(fill="both", expand=True)
        ttk.Label(payload_frame, text="Hex mode accepts spaces, colons, or hyphens.",foreground="gray").pack(anchor="w", pady=(5, 0))    
        file_frame = ttk.LabelFrame(content_panes, text="File Management", padding=10)
        content_panes.add(file_frame, weight=1)
        self.selected_audio_path = tk.StringVar(value="")
        self.file_directory = tk.StringVar(value=str(Path(__file__).resolve().parent))
        ttk.Label(file_frame, text="Directory").pack(anchor="w")
        dir_row = ttk.Frame(file_frame)
        dir_row.pack(fill="x", pady=(2, 6))
        ttk.Entry(dir_row, textvariable=self.file_directory).pack(side="left", fill="x", expand=True)
        ttk.Button(dir_row, text="Browse…", command=self.browse_file_directory).pack(side="left", padx=(5, 0))
        ttk.Label(file_frame, text="Files in directory (.wav first)").pack(anchor="w")
        self.file_list = tk.Listbox(file_frame, height=6, exportselection=False)
        self.file_list.pack(fill="both", expand=True, pady=(2, 6))
        self.file_list.bind("<<ListboxSelect>>", self.select_listed_file)
        file_buttons = ttk.Frame(file_frame)
        file_buttons.pack(fill="x")
        ttk.Button(file_buttons, text="Refresh", command=self.refresh_file_list).pack(side="left")
        ttk.Button(file_buttons, text="Select", command=self.browse_audio_file).pack(side="left", padx=(5, 0))
        ttk.Button(file_buttons, text="Clear", command=self.clear_selected_file).pack(side="left", padx=(5, 0))
        ttk.Label(file_frame, text="Assigned variable: selected_audio_path").pack(anchor="w", pady=(7, 0))
        ttk.Entry(file_frame, textvariable=self.selected_audio_path, state="readonly").pack(fill="x", pady=(2, 0))
        self.refresh_file_list()
        right_workspace = ttk.Panedwindow(right, orient="vertical")
        right_workspace.pack(fill="both", expand=True)
        operations_frame = ttk.LabelFrame(right_workspace, text="Operations — full menu", padding=8)
        right_workspace.add(operations_frame, weight=2)
        operation_specs = [
            ("Preview CCSDS Frame",self.run_preview, True),
            ("Check Connection to Spacecraft", self.test_connection, True),
            ("Transmit TM Type Telecommand", self.run_tm_telecommand, True),
            ("Transmit AD Type Telecommand", self.run_ad_telecommand, True),
            ("Dump Spacecraft EEPROM Data", self.run_eeprom_inspection, True),
            ("Pass Prediction System", self.run_pass_prediction, True),
            ("Automated Tracking System", self.run_automated_tracking, True),
            ("Breach Ground Station", self.run_groundstation_security_check, True),
            ("Demodulate AFSK 1200 Telecommand Signal", self.run_afsk_demodulator, True),
            ("Transmit AFSK 1200 Telecommand Signal", self.run_afsk_telecommand, False),
            ("Clear connection", self.run_clear, True),
            ("Exit", self.destroy, True),]
        for index, (label, command, enabled) in enumerate(operation_specs):
            button = ttk.Button(operations_frame, text=label, command=command)
            button.grid(row=index // 2, column=index % 2, sticky="ew", padx=4, pady=3)
            if not enabled:
                button.configure(state="disabled")
        operations_frame.columnconfigure(0, weight=1)
        operations_frame.columnconfigure(1, weight=1)
        output_frame = ttk.LabelFrame(right_workspace, text="Output", padding=8)
        right_workspace.add(output_frame, weight=2)
        self.output = ScrolledText(output_frame, height=10, wrap="none", font=("Consolas", 9),undo=False)
        self.output.pack(fill="both", expand=True)
        self.output.configure(state="disabled")
        terminal_frame = ttk.LabelFrame(left_detail_panes, text="Terminal / diagnostic log", padding=6)
        left_detail_panes.add(terminal_frame, weight=1)
        terminal_toolbar = ttk.Frame(terminal_frame)
        terminal_toolbar.pack(fill="x", pady=(0, 5))
        ttk.Button(terminal_toolbar, text="Clear", command=self.clear_log).pack(side="left")
        ttk.Button(terminal_toolbar, text="Copy", command=self.copy_log).pack(side="left", padx=(5, 0))
        ttk.Button(terminal_toolbar, text="Save", command=self.save_log).pack(side="left", padx=(5, 0))
        self.terminal = ScrolledText(terminal_frame, height=5, wrap="word", font=("Consolas", 9), state="disabled")
        self.terminal.pack(fill="both", expand=True)
        self.status = tk.StringVar(value="Starting…")
        ttk.Label(self, textvariable=self.status, relief="sunken",anchor="w", padding=(6, 4)).pack(fill="x", pady=(10, 0))

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Preview CCSDS Frame
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_preview(self):
        self._run_config_script("viewPacket.py", "Preview Space Packet")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Check Connection to Spacecraft
# Modified: N/A
# -------------------------------------------------------------------------------------

    def test_connection(self):
        try:
            cfg = self._get_config()
            if cfg["port"] == 0:
                raise ValueError("Set a target TCP port between 1 and 65535.")
        except ValueError as exc:
            self.log("ERROR", str(exc))
            messagebox.showerror("Connection settings", str(exc))
            return
        self.status.set(f"Testing TCP connection to {cfg['host']}:{cfg['port']}…")
        self.log("INFO", f"Testing TCP reachability to {cfg['host']}:{cfg['port']} (no application data sent)")
        threading.Thread(target=self._connection_worker, args=(cfg["host"], cfg["port"]), daemon=True).start()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Transmit TM Type Telecommand
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_tm_telecommand(self):
        self._confirm_telecommand("TM")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Transmit AD Type Telecommand
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_ad_telecommand(self):
        self._confirm_telecommand("AD")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Transmit Telecommand
# Modified: N/A
# -------------------------------------------------------------------------------------

    def _confirm_telecommand(self, command_type):
        script = "tmTelecommand.py" if command_type == "TM" else "adTelecommand.py"
        script_path = Path(__file__).resolve().parent / script
        if not script_path.is_file():
            self.log(f"{command_type} Telecommand", f"Required script not found:{script_path}")
            return
        if not messagebox.askyesno(f"Confirm {command_type} telecommand",f"This will launch {script}, which may transmit a command to the configured endpoint.\n\n" f"Target: {self.vars['host'].get().strip()}:{self.vars['port'].get().strip()}\n\n" "Continue only if you are authorised and have verified the target and payload.",parent=self,):
            self.log("INFO", f"{command_type} telecommand launch cancelled")
            return
        self._run_config_script(script, f"{command_type} Telecommand")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Dump Spacecraft EEPROM Data
# EXTRA   : "Target: {self.vars['host'].get().strip()}:{self.vars['port'].get().strip()}\n\n"
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_eeprom_inspection(self):
        if not messagebox.askyesno("Confirm EEPROM Dump Command","This will launch scalpedPlatform.py.",parent=self,):
            self.log("INFO", "EEPROM dump cancelled by user")
            return
        self._run_config_script("scalpedPlatform.py","EEPROM Dump")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Pass Prediction System
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_pass_prediction(self):
        if not messagebox.askyesno("Confirm pass prediction system","This launches firstContact.py, which may control physical antenna hardware.\n\n" f"Target: {self.vars['host'].get().strip()}:{self.vars['port'].get().strip()}\n\n"  "Only continue if you are authorised and the antenna system is safe to move.",parent=self,):
            self.log("INFO", "Pass prediction system cancelled by user")
            return
        self._run_config_script("firstContact.py", "Pass Prediction System")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Automated Tracking System
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_automated_tracking(self):
        if not messagebox.askyesno("Confirm automated tracking","This launches antennaPointing.py, which may control physical antenna hardware.\n\n" f"Target: {self.vars['host'].get().strip()}:{self.vars['port'].get().strip()}\n\n" "Only continue if you are authorised and the antenna system is safe to move.",parent=self,):
            self.log("INFO", "Automated tracking cancelled by user")
            return
        self._run_config_script("antennaPointing.py", "Automated Tracking System")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Breach Ground Station
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_groundstation_security_check(self):
        if not messagebox.askyesno("Confirm groundstation breach","This launches groundStationBreach.py, which will attempt to breach ground station systems.\n\n" f"Target: {self.vars['host'].get().strip()}:{self.vars['port'].get().strip()}\n\n" "Only continue if you are authorised and you have the appropriate permissions.",parent=self,):
            self.log("INFO", "Groundstation breach cancelled by user")
            return
        self._run_config_script("groundStationBreach.py", "Ground station breach")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Demodulate AFSK 1200 Signals
# NOTE    : Run signalFromSpace.py using the file assigned in File Management.
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_afsk_demodulator(self):
        script_path = Path(__file__).resolve().parent / "signalFromSpace.py"
        raw_path = self.selected_audio_path.get().strip()
        if not raw_path:
            messagebox.showwarning("No input file selected","Select a WAV file in File Management before running the AFSK demodulator.",parent=self)
            return
        audio_path = Path(raw_path).expanduser().resolve()
        if not audio_path.is_file():
            messagebox.showerror("Input file not found", f"The selected file does not exist:\n{audio_path}", parent=self)
            return
        if audio_path.suffix.lower() != ".wav":
            messagebox.showerror("Invalid input file", "signalFromSpace.py requires a .wav file.", parent=self)
            return
        self.status.set(f"Running AFSK demodulator on {audio_path.name}…")
        self.log("INFO", f"Starting signalFromSpace.py with selected_audio_path={audio_path}")
        self.payload_text.delete("1.0", "end")
        self.payload_text.insert("1.0", audio_path)
        if not messagebox.askyesno("Confirm AFSK 1200 Demodulator Command","This will launch signalFromSpace.py.",parent=self,):
            self.log("INFO", "AFSK 1200 demodulator cancelled by user")
            return
        self._run_config_script("signalFromSpace.py","AFSK 1200 Demodulator")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : AFSK 1200 Signal Transmission
# NOTE    : Not implemented yet
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_afsk_telecommand(self):
        if not messagebox.askyesno("Confirm AFSK 1200 signal transmission","This launches spaceOps.py, which may control physical antenna hardware.\n\n" f"Target: {self.vars['host'].get().strip()}:{self.vars['port'].get().strip()}\n\n" "Only continue if you are authorised and the antenna system is safe to move.",parent=self,):
            self.log("INFO", "AFSK 1200 signal trasnsmission cancelled by user")
            return
        self._run_config_script("spaceOps.py", "AFSK 1220 signal transmission")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : CORE
# Details : Reset screen
# Modified: N/A
# -------------------------------------------------------------------------------------

    def run_clear(self):
        if not messagebox.askyesno("Clear Connection","This will reset all connection parameters, packet counters, " "payload data and selected files to their default values.\n\nContinue?",parent=self):
            self.log("INFO", "clear connection cancelled by user")
            return
        for key, value in DEFAULTS.items():
            if key == "payload":
                continue
            self.vars[key].set(str(value))
        self.endpoint_var.set("")
        self.payload_mode.set("text")
        self.payload_text.delete("1.0", "end")
        self.payload_text.insert("1.0", DEFAULTS["payload"].decode("utf-8"))
        self.selected_audio_path.set("")
        self.file_list.selection_clear(0, "end")
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.status.set("Connection parameters reset to defaults")
        self.log("INFO", "Connection cleared — all console variables restored to defaults")
        messagebox.showinfo("Clear Connection","All console variables have been reset successfully.",parent=self)

# -------------------------------------------------------------------------------------

    def browse_file_directory(self):
        directory = filedialog.askdirectory(
            title="Choose file-management directory",
            initialdir=self.file_directory.get() or str(Path(__file__).resolve().parent),
            parent=self,)
        if directory:
            self.file_directory.set(directory)
            self.refresh_file_list()

    def refresh_file_list(self):
        directory = Path(self.file_directory.get()).expanduser()
        self.file_list.delete(0, "end")
        self._listed_files = []
        if not directory.is_dir():
            self.log("WARNING", f"File-management directory does not exist: {directory}")
            return
        try:
            files = sorted((item for item in directory.iterdir() if item.is_file()),key=lambda item: (item.suffix.lower() != ".wav", item.name.lower()))
        except OSError as exc:
            messagebox.showerror("File management", f"Cannot list directory:\n{exc}", parent=self)
            return
        self._listed_files = files
        for item in files:
            suffix = "  *" if item.suffix.lower() == ".wav" else ""
            self.file_list.insert("end", item.name + suffix)
        self.log("INFO", f"File list refreshed: {directory} ({len(files)} files)")

    def select_listed_file(self, _event=None):
        selection = self.file_list.curselection()
        if not selection:
            return
        path = self._listed_files[selection[0]].resolve()
        self.selected_audio_path.set(str(path))
        self.log("INFO", f"Assigned selected_audio_path = {path}")
        self.status.set(f"File assigned: {path.name}")

    def browse_audio_file(self):
        path = filedialog.askopenfilename(
            title="Select WAV audio file",
            initialdir=self.file_directory.get() or str(Path(__file__).resolve().parent),
            filetypes=[("WAV audio", "*.wav"), ("All files", "*.*")],
            parent=self,)
        if path:
            selected = Path(path).expanduser().resolve()
            self.selected_audio_path.set(str(selected))
            self.file_directory.set(str(selected.parent))
            self.refresh_file_list()
            self.status.set(f"File assigned: {selected.name}")
            self.log("INFO", f"Assigned selected_audio_path = {selected}")

    def clear_selected_file(self):
        self.selected_audio_path.set("")
        self.file_list.selection_clear(0, "end")
        self.status.set("Selected file cleared")
        self.log("INFO", "Cleared selected_audio_path")

# -------------------------------------------------------------------------------------

    def _run_config_script(self, script_name, display_name):
        script_path = Path(__file__).resolve().parent / script_name
        if not script_path.is_file():
            self.log(display_name, f"Required script was not found next to this GUI:{script_path}")
            return
        try:
            cfg = self._get_config()
        except ValueError as exc:
            messagebox.showerror("Configuration error", str(exc))
            return
        config_for_script = dict(cfg)
        payload = config_for_script.get("payload", b"")
        config_for_script["payload"] = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
        self.status.set(f"Running {display_name}…")
        self.log("INFO", f"Starting {display_name} using {script_name}")
        threading.Thread(target=self._script_worker,args=(str(script_path), json.dumps(config_for_script), display_name),daemon=True,).start()

    def _script_worker(self, script_path, config_json, display_name):
        try:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            self.after(0, self._begin_live_output, display_name)
            process = subprocess.Popen(
                [sys.executable, "-u", script_path, config_json],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=str(Path(script_path).resolve().parent),
                env=env,)
            if process.stdout is not None:
                for line in iter(process.stdout.readline, ""):
                    self.after(0, self._append_live_output, line)
                process.stdout.close()
            return_code = process.wait()
            title = (f"{display_name.upper()} — " f"{'COMPLETED' if return_code == 0 else 'EXIT CODE ' + str(return_code)}")
            self.after(0,self._finish_live_output,title,f"{display_name}: exit code {return_code}",)
            self.log("INFO" if return_code == 0 else "ERROR",f"{display_name} finished with exit code {return_code}",)
        except OSError as exc:
            message = str(exc)
            self.after(0,self._append_live_output,f"Could not start {display_name}: {message}\n",)
            self.after(0, self.status.set, f"{display_name}: failed to start")
            self.log("ERROR", f"Could not start {display_name}: {message}")

    def _begin_live_output(self, display_name):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end",f"{display_name.upper()} — RUNNING\n" + separator + "\n\n",)
        self.output.see("end")
        self.output.configure(state="disabled")
        self.status.set(f"Running {display_name}…")

    def _append_live_output(self, text):
        self.output.configure(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _finish_live_output(self, title, status_text):
        self._append_live_output("\n" + separator + "\n" + title + "\n")
        self.status.set(status_text)

# -------------------------------------------------------------------------------------

    def _audio_script_worker(self, script_path, audio_path, display_name):
        try:
            result = subprocess.run([sys.executable, script_path, audio_path],capture_output=True, text=True, timeout=300, check=False,cwd=str(Path(script_path).resolve().parent),)
            combined = result.stdout or ""
            if result.stderr:
                combined += "\n[stAutomated Tracking Systemderr]\n" + result.stderr
            if not combined.strip():
                combined = "(The script produced no console output.)"
            title = f"{display_name.upper()} — {'COMPLETED' if result.returncode == 0 else 'EXIT CODE ' + str(result.returncode)}"
            self.after(0, lambda: self._write(title + "\n" + separator + "\n\n" + combined))
            self.after(0, lambda: self.status.set(f"{display_name}: exit code {result.returncode}"))
            self.log("INFO" if result.returncode == 0 else "ERROR",
                     f"{display_name} finished with exit code {result.returncode}")
        except subprocess.TimeoutExpired:
            self.after(0, lambda: self._write(f"{display_name.upper()}\n\nStopped waiting after 5 minutes."))
            self.after(0, lambda: self.status.set(f"{display_name}: timed out"))
            self.log("ERROR", f"{display_name} timed out after 300 seconds")
        except OSError as exc:
            message = str(exc)
            self.after(0, lambda: self._write(f"Could not start {display_name}: {message}"))
            self.after(0, lambda: self.status.set(f"{display_name}: failed to start"))
            self.log("ERROR", f"Could not start {display_name}: {message}")

    def apply_endpoint(self):
        raw = self.endpoint_var.get().strip()
        if not raw:
            return
        host, separator, port_text = raw.rpartition(":")
        if not separator or not host.strip() or not port_text.strip():
            messagebox.showerror("Invalid endpoint", "Enter the endpoint as HOST:PORT, for example 154.57.164.68:33366.",parent=self,)
            return
        host = host.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            port = int(port_text.strip(), 10)
        except ValueError:
            messagebox.showerror("Invalid endpoint", "The port must be a number from 1 to 65535.", parent=self)
            return
        if not 1 <= port <= 65535:
            messagebox.showerror("Invalid endpoint", "The port must be between 1 and 65535.", parent=self)
            return
        self.vars["host"].set(host)
        self.vars["port"].set(str(port))
        self.endpoint_var.set("")
        self.status.set(f"Target set to {host}:{port}")
        self.log("INFO", f"Endpoint split into target host {host} and TCP port {port}")

    def _load_defaults(self):
        self.endpoint_var.set("")
        for key, value in DEFAULTS.items():
            if key == "payload":
                continue
            self.vars[key].set(str(value))
        self.payload_mode.set("text")
        self.payload_text.delete("1.0", "end")
        self.payload_text.insert("1.0", "PAYLOAD")
        self._write("Defaults loaded.", "INFO")
        self.status.set("Defaults loaded")

    def _write(self, text, level="INFO"):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", text.rstrip() + "\n")
        self.output.configure(state="disabled")
        self.log(level, text.splitlines()[0] if text.splitlines() else "")

    def log(self, level, message):
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"[{stamp}] [{level.upper()}] {message}")

    def _drain_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.terminal.configure(state="normal")
                self.terminal.insert("end", line + "\n")
                self.terminal.see("end")
                self.terminal.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self._drain_log_queue)

    def clear_log(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")
        self.log("INFO", "Terminal log cleared")

    def copy_log(self):
        content = self.terminal.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(content)
        self.log("SUCCESS", "Terminal log copied to clipboard")

    def save_log(self):
        path = filedialog.asksaveasfilename(
            title="Save diagnostic log", defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text(self.terminal.get("1.0", "end-1c"), encoding="utf-8")
            self.log("SUCCESS", f"Log saved to {path}")
        except OSError as exc:
            self.log("ERROR", f"Could not save log: {exc}")
            messagebox.showerror("Save log failed", str(exc))

    def _connection_worker(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=4.0):
                self.log("SUCCESS", f"TCP connection succeeded: {host}:{port}; socket closed without sending data")
                self.after(0, lambda: self.status.set(f"TCP reachable: {host}:{port}"))
        except (OSError, TimeoutError) as exc:
            self.log("ERROR", f"TCP connection failed for {host}:{port}: {exc}")
            self.after(0, lambda: self.status.set(f"TCP connection failed: {host}:{port}"))

    def _get_config(self):
        if self.endpoint_var.get().strip():
            self.apply_endpoint()
            if self.endpoint_var.get().strip():
                raise ValueError("Correct the Target endpoint field or clear it before continuing.")
        result = {}
        ranges = {"port": (1, 65535),"port2": (1, 65535),"spacecraft_id": (0, 1023),"virtual_channel_id": (0, 63),"apid": (0, 2047),"packet_count": (0, 16383),"tc_packet_count": (0, 255),}
        result["host"] = self.vars["host"].get().strip()
        if not result["host"]:
            raise ValueError("Target host cannot be empty.")
        for key, (low, high) in ranges.items():
            raw = self.vars[key].get().strip()
            try:
                value = int(raw, 0)
            except ValueError:
                raise ValueError(f"{key.replace('_', ' ').title()} must be an integer.")
            if not low <= value <= high:
                raise ValueError(f"{key.replace('_', ' ').title()} must be between {low} and {high}.")
            result[key] = value
        raw_payload = self.payload_text.get("1.0", "end-1c")
        if self.payload_mode.get() == "text":
            payload = raw_payload.encode("utf-8")
        else:
            cleaned = raw_payload.replace(" ", "").replace(":", "").replace("-", "").replace("_", "")
            try:
                payload = bytes.fromhex(cleaned)
            except ValueError:
                raise ValueError("Payload is not valid hexadecimal.")
        if not payload:
            raise ValueError("Payload cannot be empty.")
        result["payload"] = payload
        return result

    @staticmethod
    def _build(cfg):
        packet = generate_space_packet(cfg["apid"], cfg["packet_count"], cfg["payload"])
        frame = generate_tc_frame(cfg["spacecraft_id"], cfg["virtual_channel_id"],cfg["tc_packet_count"], packet)
        return packet, frame

if __name__ == "__main__":
    app = SpacecraftGUI()
    app.mainloop()