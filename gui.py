"""DNS Tunneling Detection - Desktop GUI Application

A Tkinter-based GUI for capturing DNS traffic and analyzing it for tunneling attempts.
"""
import subprocess
import sys
import os
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
from pathlib import Path
import csv
import threading
import time


class DNSTunnelingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Tunneling Detection")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Dark gray background theme
        self.bg_color = "#2b2b2b"
        self.button_color = "#4a4a4a"
        self.text_color = "#ffffff"
        self.accent_color = "#5a9"
        self.listbox_bg = "#1e1e1e"
        
        self.root.configure(bg=self.bg_color)
        
        # Track capture process
        self.capture_process = None
        self.monitoring = False
        
        # Project root directory
        self.project_root = Path(__file__).parent
        
        # Track last read position for CSV
        self.last_capture_count = 0
        
        self.setup_ui()
        self.start_monitoring()
    
    def setup_ui(self):
        """Create and layout all UI components."""
        # Title label
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(pady=10, fill="x")
        
        title_label = tk.Label(
            title_frame,
            text="DNS Tunneling Detection Tool",
            font=("Arial", 18, "bold"),
            bg=self.bg_color,
            fg=self.text_color
        )
        title_label.pack()
        
        # Button frame (horizontal layout)
        button_frame = tk.Frame(self.root, bg=self.bg_color)
        button_frame.pack(pady=10, padx=20, fill="x")
        
        # Start Capture button
        self.start_button = tk.Button(
            button_frame,
            text="Start Capture",
            font=("Arial", 14, "bold"),
            bg=self.accent_color,
            fg=self.text_color,
            activebackground="#6bb",
            activeforeground=self.text_color,
            relief="raised",
            bd=3,
            padx=15,
            pady=10,
            command=self.start_capture,
            cursor="hand2"
        )
        self.start_button.pack(side="left", padx=5, fill="x", expand=True)
        
        # Stop Capture button (initially hidden)
        self.stop_button = tk.Button(
            button_frame,
            text="Stop Capture",
            font=("Arial", 14, "bold"),
            bg="#c44",
            fg=self.text_color,
            activebackground="#e66",
            activeforeground=self.text_color,
            relief="raised",
            bd=3,
            padx=15,
            pady=10,
            command=self.stop_capture,
            cursor="hand2"
        )
        
        # Analyse button
        self.analyse_button = tk.Button(
            button_frame,
            text="Analyse",
            font=("Arial", 14, "bold"),
            bg=self.button_color,
            fg=self.text_color,
            activebackground="#5a5a5a",
            activeforeground=self.text_color,
            relief="raised",
            bd=3,
            padx=15,
            pady=10,
            command=self.analyse,
            cursor="hand2"
        )
        self.analyse_button.pack(side="left", padx=5, fill="x", expand=True)
        
        # Refresh button
        refresh_button = tk.Button(
            button_frame,
            text="Refresh",
            font=("Arial", 14, "bold"),
            bg="#666",
            fg=self.text_color,
            activebackground="#777",
            activeforeground=self.text_color,
            relief="raised",
            bd=3,
            padx=15,
            pady=10,
            command=self.refresh_all,
            cursor="hand2"
        )
        refresh_button.pack(side="left", padx=5, fill="x", expand=True)
        
        # Main content area with notebook (tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Style the notebook
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', background=self.button_color, foreground=self.text_color, padding=[20, 10])
        style.map('TNotebook.Tab', background=[('selected', self.accent_color)])
        
        # Tab 1: Captured Queries
        captured_frame = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(captured_frame, text="Captured Queries")
        
        captured_label = tk.Label(
            captured_frame,
            text="Live DNS Queries",
            font=("Arial", 12, "bold"),
            bg=self.bg_color,
            fg=self.text_color
        )
        captured_label.pack(pady=5)
        
        # Scrollable text widget for captured queries
        self.captured_text = scrolledtext.ScrolledText(
            captured_frame,
            bg=self.listbox_bg,
            fg="#0f0",
            font=("Consolas", 10),
            wrap=tk.WORD,
            height=20,
            insertbackground=self.text_color
        )
        self.captured_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Status label for captured queries
        self.captured_status = tk.Label(
            captured_frame,
            text="No queries captured yet",
            font=("Arial", 9),
            bg=self.bg_color,
            fg="#aaa"
        )
        self.captured_status.pack(pady=5)
        
        # Tab 2: Suspicious Queries
        suspicious_frame = tk.Frame(notebook, bg=self.bg_color)
        notebook.add(suspicious_frame, text="Suspicious Queries")
        
        suspicious_label = tk.Label(
            suspicious_frame,
            text="Detected Suspicious DNS Queries",
            font=("Arial", 12, "bold"),
            bg=self.bg_color,
            fg=self.text_color
        )
        suspicious_label.pack(pady=5)
        
        # Scrollable text widget for suspicious queries
        self.suspicious_text = scrolledtext.ScrolledText(
            suspicious_frame,
            bg=self.listbox_bg,
            fg="#f00",
            font=("Consolas", 10),
            wrap=tk.WORD,
            height=20,
            insertbackground=self.text_color
        )
        self.suspicious_text.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Status label for suspicious queries
        self.suspicious_status = tk.Label(
            suspicious_frame,
            text="No analysis performed yet",
            font=("Arial", 9),
            bg=self.bg_color,
            fg="#aaa"
        )
        self.suspicious_status.pack(pady=5)
    
    def start_capture(self):
        """Start the DNS capture process."""
        capture_script = self.project_root / "capture.py"
        
        if not capture_script.exists():
            messagebox.showerror(
                "Error",
                f"Capture script not found:\n{capture_script}\n\nPlease ensure capture.py exists in the project directory."
            )
            return
        
        try:
            # Start capture process with visible console window
            # This allows the script to run properly and show any errors
            if sys.platform == "win32":
                # On Windows, create a new console window so we can see the output
                self.capture_process = subprocess.Popen(
                    [sys.executable, str(capture_script)],
                    cwd=str(self.project_root),
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            else:
                # On Linux/Mac, run in background but allow output
                self.capture_process = subprocess.Popen(
                    [sys.executable, str(capture_script)],
                    cwd=str(self.project_root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            # Give the process a moment to start, then verify it's running
            time.sleep(0.5)
            if self.capture_process.poll() is not None:
                # Process already terminated (error)
                try:
                    stdout, stderr = self.capture_process.communicate(timeout=1)
                    error_msg = ""
                    if stderr:
                        error_msg = stderr.decode('utf-8', errors='ignore')
                    if stdout:
                        error_msg += "\n" + stdout.decode('utf-8', errors='ignore')
                    if not error_msg:
                        error_msg = "Process exited immediately. Check console for details."
                except Exception:
                    error_msg = "Process exited immediately. Check console window for details."
                
                messagebox.showerror(
                    "Capture Failed",
                    f"Capture process exited immediately:\n{error_msg}\n\nMake sure you have administrator privileges and that Npcap/WinPcap is installed."
                )
                self.capture_process = None
                return
            
            # Hide Start button and show Stop button
            self.start_button.pack_forget()
            self.stop_button.pack(side="left", padx=5, fill="x", expand=True)
            
            self.monitoring = True
            self.captured_text.delete(1.0, tk.END)
            self.captured_text.insert(tk.END, "Capture started... Waiting for DNS queries...\n\n")
            self.last_capture_count = 0
            
            messagebox.showinfo(
                "Capture Started",
                "DNS capture has started.\n\nA console window will show capture progress.\nQueries will appear in the 'Captured Queries' tab."
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to start capture:\n{str(e)}\n\nMake sure you have administrator privileges and that capture.py exists."
            )
    
    def stop_capture(self):
        """Stop the running capture process."""
        if self.capture_process is None:
            return
        
        try:
            # Check if process is still running
            if self.capture_process.poll() is None:
                # Process is still running, terminate it
                if sys.platform == "win32":
                    # On Windows, use taskkill to ensure it's terminated
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(self.capture_process.pid)],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                    except Exception:
                        # Fallback to regular terminate
                        self.capture_process.terminate()
                        try:
                            self.capture_process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            self.capture_process.kill()
                else:
                    # On Linux/Mac
                    self.capture_process.terminate()
                    try:
                        self.capture_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.capture_process.kill()
                        self.capture_process.wait()
            
            self.capture_process = None
            self.monitoring = False
            
            # Hide Stop button and show Start button
            self.stop_button.pack_forget()
            self.start_button.pack(side="left", padx=5, fill="x", expand=True)
            
            messagebox.showinfo(
                "Capture Stopped",
                "DNS capture has been stopped successfully."
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to stop capture:\n{str(e)}"
            )
            # Reset UI state anyway
            self.capture_process = None
            self.monitoring = False
            self.stop_button.pack_forget()
            self.start_button.pack(side="left", padx=5, fill="x", expand=True)
    
    def load_captured_queries(self):
        """Load and display captured queries from dns_log.csv."""
        log_file = self.project_root / "dns_log.csv"
        
        if not log_file.exists():
            return
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                # Only update if we have new rows
                if len(rows) > self.last_capture_count:
                    new_rows = rows[self.last_capture_count:]
                    self.last_capture_count = len(rows)
                    
                    for row in new_rows:
                        timestamp = row.get('timestamp', 'N/A')
                        qname = row.get('qname', 'N/A')
                        src_ip = row.get('src_ip', 'N/A')
                        dst_ip = row.get('dst_ip', 'N/A')
                        is_response = row.get('is_response', '0')
                        
                        query_type = "RESPONSE" if is_response == '1' else "QUERY"
                        color_tag = "response" if is_response == '1' else "query"
                        
                        line = f"[{timestamp}] {query_type}: {qname}\n"
                        line += f"    Source: {src_ip} → Destination: {dst_ip}\n\n"
                        
                        self.captured_text.insert(tk.END, line)
                        self.captured_text.see(tk.END)
                    
                    # Update status
                    self.captured_status.config(
                        text=f"Total queries captured: {len(rows)}",
                        fg="#0f0"
                    )
                elif len(rows) == 0:
                    self.captured_status.config(
                        text="No queries captured yet",
                        fg="#aaa"
                    )
                else:
                    self.captured_status.config(
                        text=f"Total queries captured: {len(rows)}",
                        fg="#0f0"
                    )
        except Exception as e:
            # Silently handle errors (file might be locked or being written)
            pass
    
    def load_suspicious_queries(self):
        """Load and display suspicious queries from dns_predictions.csv."""
        predictions_file = self.project_root / "dns_predictions.csv"
        
        if not predictions_file.exists():
            self.suspicious_text.delete(1.0, tk.END)
            self.suspicious_text.insert(tk.END, "No analysis results available.\n\nRun 'Analyse' to detect suspicious queries.")
            self.suspicious_status.config(text="No analysis performed yet", fg="#aaa")
            return
        
        try:
            with open(predictions_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                suspicious_count = 0
                total_count = 0
                
                self.suspicious_text.delete(1.0, tk.END)
                
                for row in reader:
                    total_count += 1
                    qname = row.get('qname', 'N/A')
                    prediction = row.get('prediction', '')
                    confidence = row.get('confidence', 'N/A')
                    
                    # Check if suspicious (handle emoji or text)
                    if 'Suspicious' in prediction or '🔴' in prediction:
                        suspicious_count += 1
                        line = f"⚠️  {qname}\n"
                        line += f"   Confidence: {confidence}%\n\n"
                        self.suspicious_text.insert(tk.END, line)
                
                if suspicious_count == 0:
                    self.suspicious_text.insert(
                        tk.END,
                        f"✅ No suspicious queries detected!\n\nAnalyzed {total_count} queries. All appear safe."
                    )
                    self.suspicious_status.config(
                        text=f"Analysis complete: {total_count} queries analyzed, 0 suspicious",
                        fg="#0f0"
                    )
                else:
                    self.suspicious_text.see(tk.END)
                    self.suspicious_status.config(
                        text=f"⚠️  Found {suspicious_count} suspicious queries out of {total_count} analyzed",
                        fg="#f00"
                    )
        except Exception as e:
            self.suspicious_text.delete(1.0, tk.END)
            self.suspicious_text.insert(tk.END, f"Error loading predictions: {str(e)}")
            self.suspicious_status.config(text="Error loading results", fg="#f00")
    
    def refresh_all(self):
        """Manually refresh both displays."""
        self.load_captured_queries()
        self.load_suspicious_queries()
    
    def start_monitoring(self):
        """Start background thread to monitor CSV files."""
        def monitor():
            while True:
                if self.monitoring or True:  # Always monitor captured queries
                    self.root.after(0, self.load_captured_queries)
                time.sleep(2)  # Check every 2 seconds
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def analyse(self):
        """Run the prediction/analysis script."""
        # Check if capture has been run (dns_log.csv exists)
        log_file = self.project_root / "dns_log.csv"
        
        if not log_file.exists() or log_file.stat().st_size == 0:
            messagebox.showwarning(
                "No Data",
                "No DNS capture data found.\n\nPlease run 'Start Capture' first to collect DNS queries before analyzing."
            )
            return
        
        # Check if model exists
        model_file = self.project_root / "best_dns_model.pkl"
        if not model_file.exists():
            messagebox.showerror(
                "Model Not Found",
                f"Trained model not found:\n{model_file}\n\nPlease run training first (train_best.py) to create the model."
            )
            return
        
        predict_script = self.project_root / "predict.py"
        if not predict_script.exists():
            messagebox.showerror(
                "Error",
                f"Prediction script not found:\n{predict_script}\n\nPlease ensure predict.py exists in the project directory."
            )
            return
        
        # Show loading message
        self.suspicious_text.delete(1.0, tk.END)
        self.suspicious_text.insert(tk.END, "Running analysis... Please wait...\n")
        self.suspicious_status.config(text="Analyzing...", fg="#ff0")
        self.root.update()  # Force UI update
        
        try:
            # Run prediction script - show console for output
            if sys.platform == "win32":
                # On Windows, show console window so user can see progress
                result = subprocess.call(
                    [sys.executable, str(predict_script)],
                    cwd=str(self.project_root),
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            else:
                # On Linux/Mac, run with output visible
                result = subprocess.call(
                    [sys.executable, str(predict_script)],
                    cwd=str(self.project_root)
                )
            
            if result == 0:
                # Load results immediately
                self.load_suspicious_queries()
                messagebox.showinfo(
                    "Analysis Completed",
                    "Analysis completed successfully!\n\nCheck the 'Suspicious Queries' tab for results."
                )
            else:
                messagebox.showerror(
                    "Analysis Failed",
                    f"Analysis script exited with error code {result}.\n\nCheck the console window for details."
                )
                self.suspicious_status.config(text="Analysis failed", fg="#f00")
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to run analysis:\n{str(e)}"
            )
            self.suspicious_status.config(text="Error during analysis", fg="#f00")
    
    def on_closing(self):
        """Handle window closing event."""
        if self.capture_process is not None:
            if messagebox.askokcancel("Quit", "Capture is still running. Stop it and quit?"):
                self.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    app = DNSTunnelingGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
