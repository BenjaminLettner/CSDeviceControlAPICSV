import os
import json
import csv
import requests
import logging
import threading
import stat
import time
import sys
import subprocess
from tkinter import Tk, Label, filedialog, messagebox, StringVar, Toplevel, Entry
from tkinter.ttk import Button, Style, Combobox
from cryptography.fernet import Fernet

# Configure logging to capture essential information
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s'
)

# Define color constants for the red theme
PRIMARY_RED = "#D32F2F"    # Primary red color
WHITE = "#FFFFFF"          # White color
DARK_GRAY = "#555555"      # Dark gray for text
LIGHT_BG = "#F5F5F5"       # Light background


class EncryptionManager:
    """Manages encryption and decryption of configuration files."""

    def __init__(self, key_file="key.key", encrypted_file="config.enc", plain_config="config.json"):
        self.key_file = key_file
        self.encrypted_file = encrypted_file  # Make sure it's initialized here
        self.plain_config = plain_config

    def generate_key(self):
        try:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
            os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)  # Restrict file permissions
            logging.info(f"Encryption key generated and saved to {self.key_file}.")
        except Exception as e:
            logging.error(f"Error generating key: {e}")
            raise

    def save_and_encrypt_config(self, client_id, client_secret, csv_params=None):
        try:
            config_data = {
                "client_id": client_id,
                "client_secret": client_secret
            }
            if csv_params:
                config_data["csv_params"] = csv_params
            else:
                existing_config = self.load_config(silent=True)
                if existing_config and "csv_params" in existing_config:
                    config_data["csv_params"] = existing_config["csv_params"]

            with open(self.plain_config, "w", encoding="utf-8") as config_file:
                json.dump(config_data, config_file, indent=4)
            logging.info(f"Configuration saved to {self.plain_config}.")

            if not os.path.exists(self.key_file):
                self.generate_key()

            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            with open(self.plain_config, "rb") as config_file:
                config_bytes = config_file.read()
            encrypted_data = fernet.encrypt(config_bytes)

            with open(self.encrypted_file, "wb") as enc_file:
                enc_file.write(encrypted_data)
            logging.info(f"Configuration encrypted and saved as '{self.encrypted_file}'.")

            os.remove(self.plain_config)  # Remove plain config
            logging.info(f"Removed plain config file '{self.plain_config}' for security.")
        except Exception as e:
            logging.error(f"Error saving and encrypting configuration: {e}")
            raise

    def load_config(self, silent=False):
        if not os.path.exists(self.encrypted_file):
            if not silent:
                messagebox.showerror("Error", "Encrypted config file not found.")
            logging.error("Encrypted config file not found.")
            return None
        if not os.path.exists(self.key_file):
            if not silent:
                messagebox.showerror("Error", "Encryption key file not found.")
            logging.error("Encryption key file not found.")
            return None
        try:
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            with open(self.encrypted_file, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            config = json.loads(decrypted_data.decode("utf-8"))
            return config
        except Exception as e:
            if not silent:
                messagebox.showerror("Error", f"Failed to load/decrypt configuration: {e}")
            logging.error(f"Failed to load/decrypt configuration: {e}")
            return None

    def encrypt_config_file(self, config_path="config.json"):
        if not os.path.exists(config_path):
            messagebox.showerror("Error", f"'{config_path}' does not exist.")
            logging.error(f"'{config_path}' does not exist.")
            return
        try:
            with open(config_path, "rb") as f:
                config_data = f.read()

            if not os.path.exists(self.key_file):
                self.generate_key()

            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(config_data)

            with open(self.encrypted_file, "wb") as enc_file:
                enc_file.write(encrypted_data)

            logging.info(f"'{config_path}' encrypted successfully as '{self.encrypted_file}'.")
            messagebox.showinfo("Success", f"'{config_path}' has been encrypted as '{self.encrypted_file}'.")
        except Exception as e:
            logging.error(f"Error encrypting config file: {e}")
            messagebox.showerror("Error", f"An error occurred during encryption: {e}")

    def decrypt_config(self, output_path="config.json"):
        if not os.path.exists(self.encrypted_file):
            messagebox.showerror("Error", "Encrypted config file not found.")
            logging.error("Encrypted config file not found.")
            return
        if not os.path.exists(self.key_file):
            messagebox.showerror("Error", "Encryption key file not found.")
            logging.error("Encryption key file not found.")
            return
        try:
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            with open(self.encrypted_file, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            with open(output_path, "wb") as f_out:
                f_out.write(decrypted_data)
            logging.info(f"Config file decrypted successfully and saved as '{output_path}'.")
            messagebox.showinfo("Success", f"Config file decrypted and saved as '{output_path}'.")
        except Exception as e:
            logging.error(f"Error decrypting config file: {e}")
            messagebox.showerror("Error", f"An error occurred during decryption: {e}")


class APIClient:
    """Handles interactions with the CrowdStrike API."""

    def __init__(self, base_url="https://api.eu-1.crowdstrike.com"):
        self.base_url = base_url
        self.access_token = None

    def get_access_token(self, client_id, client_secret):
        try:
            response = requests.post(
                f"{self.base_url}/oauth2/token",
                data={"client_id": client_id, "client_secret": client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            self.access_token = response.json().get("access_token")
            logging.info("Access token obtained successfully.")
            return self.access_token
        except requests.HTTPError as http_err:
            logging.error(f"HTTP error obtaining token: {http_err}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error obtaining token: {e}")
            raise

    def get_device_control_policies(self):
        if not self.access_token:
            logging.error("Access token not set for device control policies fetch.")
            raise ValueError("Access token is not set.")
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        try:
            url = f"{self.base_url}/policy/combined/device-control/v1"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            policies = response.json().get("resources", [])
            logging.info(f"Retrieved {len(policies)} device control policies.")
            return policies
        except requests.HTTPError as http_err:
            logging.error(f"HTTP error retrieving policies: {http_err}")
            raise
        except Exception as e:
            logging.error(f"Error retrieving policies: {e}")
            raise


class DeviceControlApp:
    """Manages the GUI, user interactions, and coordination between components."""

    def __init__(self, root):
        self.root = root
        self.root.geometry("700x700")
        self.root.configure(bg=LIGHT_BG)

        self.init_styles()
        self.encryption_manager = EncryptionManager()
        self.api_client = APIClient()

        self.CSV_FILEPATH = None
        self.selected_policy = StringVar()
        self.policy_id_mapping = {}

        self.status_label = None
        self.summary_label = None
        self.policy_dropdown = None
        self.process_button = None

        # Default CSV import params
        self.csv_params = {
            "delimiter": ",",
            "encoding": "utf-8",
            "vendor_id_column": "Vendor ID",
            "model_product_id_column": "Model/Product ID",
            "serial_number_column": "Serial Number"
        }

        # Hide the main window initially if no config
        self.root.withdraw()

        if not os.path.exists(self.encryption_manager.encrypted_file):
            self.setup_config_dialog()
        else:
            self.root.deiconify()
            config = self.encryption_manager.load_config()
            if config and "csv_params" in config:
                self.csv_params = config["csv_params"]
            threading.Thread(target=self.fetch_policies, daemon=True).start()
            self.main_menu()

    def setup_config_dialog(self):
        def submit_credentials():
            client_id = client_id_var.get().strip()
            client_secret = client_secret_var.get().strip()

            if not client_id or not client_secret:
                messagebox.showerror("Error", "Both Client ID and Client Secret are required.")
                return
            try:
                # Test authentication quickly
                test_client = APIClient()
                token = test_client.get_access_token(client_id, client_secret)
                if not token:
                    raise ValueError("No access token returned")
            except Exception as e:
                messagebox.showerror("Error", f"Authentication failed: {e}")
                return
            try:
                self.encryption_manager.save_and_encrypt_config(client_id, client_secret, self.csv_params)
                messagebox.showinfo("Success", "Configuration saved & encrypted.")
                conf_win.destroy()
                self.root.deiconify()
                threading.Thread(target=self.fetch_policies, daemon=True).start()
                self.main_menu()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save config: {e}")

        conf_win = Toplevel(self.root)
        conf_win.title("Setup Configuration")
        conf_win.geometry("500x500")
        conf_win.configure(bg=LIGHT_BG)
        conf_win.grab_set()

        Label(conf_win, text="Enter Configuration", font=("Segoe UI", 16, "bold"),
              bg=LIGHT_BG, fg=PRIMARY_RED).pack(pady=10)

        info_frame = Label(conf_win, bg=LIGHT_BG)
        info_frame.pack(pady=(0, 10), padx=10, fill='x')

        info_text = (
            "Enter API Client ID and Secret.\n"
            "Needs Read/Write for Device Control Policies.\n"
            "Check CrowdStrike docs for API client creation steps."
        )
        Label(info_frame, text=info_text, font=("Segoe UI", 10),
              bg=LIGHT_BG, wraplength=480, justify="left").pack(pady=(0, 5))

        def doc_link(e):
            webbrowser.open_new("https://falcon.eu-1.crowdstrike.com/documentation/page/te8afcf6/api-integration")

        doc_lbl = Label(info_frame, text="Crowdstrike API Client Docs",
                        font=("Segoe UI", 10, "underline"), fg=PRIMARY_RED, cursor="hand2", bg=LIGHT_BG)
        doc_lbl.pack()
        doc_lbl.bind("<Button-1>", doc_link)

        Label(conf_win, text="Client ID:", font=("Segoe UI", 12, "bold"),
              bg=LIGHT_BG, fg=DARK_GRAY).pack(pady=(10, 5))
        client_id_var = StringVar()
        Entry(conf_win, textvariable=client_id_var, width=50,
              font=("Segoe UI", 12)).pack(pady=5)

        Label(conf_win, text="Client Secret:", font=("Segoe UI", 12, "bold"),
              bg=LIGHT_BG, fg=DARK_GRAY).pack(pady=(10, 5))
        client_secret_var = StringVar()
        Entry(conf_win, textvariable=client_secret_var, width=50, show="*",
              font=("Segoe UI", 12)).pack(pady=5)

        Button(conf_win, text="Submit", style="RoundedBlue.TButton",
               command=submit_credentials).pack(pady=20)

        self.root.wait_window(conf_win)

    def init_styles(self):
        style = Style()
        style.theme_use("clam")
        style.configure("Rounded.TButton", font=("Segoe UI", 12), padding=10, foreground=WHITE, background=PRIMARY_RED)
        style.configure("RoundedBlue.TButton", font=("Segoe UI", 12), padding=10,
                        foreground=WHITE, background=PRIMARY_RED)
        style.map("RoundedBlue.TButton",
                  background=[('active', "#B71C1C")])

    def fetch_policies(self):
        try:
            self.update_status("Status: Obtaining access token...")
            cfg = self.encryption_manager.load_config()
            if not cfg:
                self.update_status("Failed to load config")
                return

            token = self.api_client.get_access_token(cfg["client_id"], cfg["client_secret"])
            if not token:
                self.update_status("Token fetch failed.")
                return

            self.update_status("Fetching device control policies...")
            policies = self.api_client.get_device_control_policies()
            if not policies:
                self.update_status("No device control policies found.")
                return

            custom_policies = [p for p in policies if p.get("name") != "platform_default"]
            if not custom_policies:
                self.update_status("No custom policies available.")
                return

            policy_names = [f"{p['name']} ({p['id']})" for p in custom_policies]
            self.policy_id_mapping = {f"{p['name']} ({p['id']})": p for p in custom_policies}
            self.root.after(0, self.update_policy_dropdown, policy_names)
            self.update_status("Policies loaded successfully.")
        except Exception as e:
            logging.error(f"Policy fetch error: {e}")
            self.update_status("Error fetching policies.")
            messagebox.showerror("Error", str(e))

    def update_policy_dropdown(self, policy_names):
        if self.policy_dropdown:
            self.policy_dropdown['values'] = policy_names
            if policy_names:
                self.policy_dropdown.current(0)
                self.on_policy_select()

    def select_csv_file(self):
        path = filedialog.askopenfilename(title="Select CSV File",
                                          filetypes=[("CSV Files", "*.csv")])
        if path:
            self.CSV_FILEPATH = path
            messagebox.showinfo("File Selected", f"Selected file: {path}")
            logging.info(f"CSV selected: {path}")
            self.update_status(f"Selected CSV: {os.path.basename(path)}")
            self.update_summary("0 devices processed")

    def process_csv_and_update_policy(self):
        if not self.CSV_FILEPATH:
            messagebox.showerror("Error", "No CSV file selected.")
            self.update_status("No CSV selected")
            self.update_summary("0 devices processed")
            return

        if not self.selected_policy.get():
            messagebox.showerror("Error", "No policy selected.")
            self.update_status("No policy selected")
            self.update_summary("0 devices processed")
            return

        pol = self.policy_id_mapping.get(self.selected_policy.get())
        if not pol:
            messagebox.showerror("Error", "Policy not found.")
            self.update_status("Policy not found")
            self.update_summary("0 devices processed")
            return

        threading.Thread(
            target=self._process_csv_and_update_policy_thread,
            args=(pol,),
            daemon=True
        ).start()

    def _process_csv_and_update_policy_thread(self, selected_policy):
        """
        Direct requests.patch() call to /policy/entities/device-control/v1.
        """
        try:
            self.update_status("Status: Processing CSV...")
            self.update_summary("Summary: 0 devices processed")

            success_count = 0
            failure_count = 0
            total_devices = 0
            failed_devices = []

            # Current classes from selected policy (to append exceptions)
            current_classes = selected_policy.get("settings", {}).get("classes", [])
            class_mapping = {cls.get("id"): cls for cls in current_classes}

            # 1) Load config, get token
            config = self.encryption_manager.load_config(silent=True)
            if not config:
                raise ValueError("Config not loaded. Cannot proceed.")

            token = self.api_client.get_access_token(config["client_id"], config["client_secret"])
            if not token:
                raise ValueError("Failed to obtain token for patch call.")

            policy_id = selected_policy.get("id")

            with open(self.CSV_FILEPATH, "r", encoding=self.csv_params["encoding"]) as cf:
                csv_reader = csv.DictReader(cf, delimiter=self.csv_params["delimiter"])

                vend_col = self.csv_params["vendor_id_column"]
                prod_col = self.csv_params["model_product_id_column"]
                sn_col = self.csv_params["serial_number_column"]

                required_columns = {vend_col, prod_col, sn_col, "Identifier"}
                if not required_columns.issubset(csv_reader.fieldnames):
                    missing = required_columns - set(csv_reader.fieldnames)
                    raise ValueError(f"CSV missing cols: {missing}")

                rows = list(csv_reader)
                total_devices = len(rows)
                self.update_summary(f"{total_devices} devices to process")

                for idx, row in enumerate(rows, start=1):
                    try:
                        vendor_hex = row.get(vend_col, "").strip()
                        product_hex = row.get(prod_col, "").strip()
                        serial_hex = row.get(sn_col, "").strip()
                        identifier = row.get("Identifier", "").strip()

                        if not all([vendor_hex, product_hex, serial_hex, identifier]):
                            raise ValueError("Missing fields in CSV row")

                        v_dec = self.hex_to_decimal(vendor_hex)
                        p_dec = self.hex_to_decimal(product_hex)
                        s_dec = self.hex_to_decimal(serial_hex)

                        combined_id = f"{v_dec}_{p_dec}_{s_dec}"

                        # Build an "exception" item, e.g. BLOCKing or ALLOWing a device
                        exception = {
                            "vendor_id": vendor_hex,
                            "vendor_id_decimal": v_dec,
                            "vendor_name": identifier,
                            "product_id": product_hex,
                            "product_id_decimal": p_dec,
                            "product_name": "Unknown Device",
                            "serial_number": s_dec,
                            "action": "BLOCK_EXECUTE",  # Change to ALLOW_EXECUTE if needed
                            "description": f"Blocked device {combined_id}",
                            "expiration_time": "2027-07-21T18:20:16Z",
                            "combined_id": combined_id
                        }

                        # Check if the exception already exists in the policy
                        # We'll check the 'exceptions' list for any existing exception with the same combined_id
                        duplicate_found = False
                        for cls in class_mapping.values():
                            for existing_exception in cls.get("exceptions", []):
                                if existing_exception.get("combined_id") == combined_id:
                                    duplicate_found = True
                                    break
                            if duplicate_found:
                                break

                        if not duplicate_found:
                            # Example: we manipulate the MASS_STORAGE class -> BLOCK_ALL
                            # Replace with ALLOW_ALL if you want to allow the device.
                            cls_id = "MASS_STORAGE"
                            desired_action = "BLOCK_ALL"

                            if cls_id in class_mapping:
                                class_mapping[cls_id]["action"] = desired_action
                                class_mapping[cls_id]["exceptions"].append(exception)
                            else:
                                new_class = {
                                    "id": cls_id,
                                    "action": desired_action,
                                    "exceptions": [exception]
                                }
                                class_mapping[cls_id] = new_class
                                current_classes.append(new_class)
                        else:
                            logging.info(f"Duplicate exception found for combined_id: {combined_id}. Skipping.")

                        # Prepare the final payload for PATCH /policy/entities/device-control/v1
                        patch_payload = {
                            "resources": [
                                {
                                    "id": policy_id,
                                    "settings": {
                                        "classes": list(class_mapping.values())
                                    }
                                }
                            ]
                        }

                        # Make direct requests.patch call to /policy/entities/device-control/v1
                        url = "https://api.eu-1.crowdstrike.com/policy/entities/device-control/v1"
                        headers = {
                            "accept": "application/json",
                            "authorization": f"Bearer {token}",
                            "Content-Type": "application/json"
                        }

                        resp = requests.patch(url, headers=headers, json=patch_payload)

                        if resp.status_code in [200, 201, 204]:
                            success_count += 1
                        else:
                            failure_count += 1
                            failed_devices.append({
                                "device": combined_id,
                                "status_code": resp.status_code,
                                "response": resp.text
                            })

                    except Exception as exc:
                        failure_count += 1
                        failed_devices.append({
                            "device": row,
                            "status_code": "N/A",
                            "response": str(exc)
                        })
                    finally:
                        self.update_summary(f"{idx} of {total_devices} devices processed")

            if failed_devices:
                with open("failed_devices.txt", "w", encoding="utf-8") as ff:
                    for failed in failed_devices:
                        ff.write(f"Device: {failed['device']}\n")
                        ff.write(f"Status Code: {failed['status_code']}\n")
                        ff.write(f"Response: {failed['response']}\n")
                        ff.write("=" * 50 + "\n")
                logging.warning(f"{len(failed_devices)} devices failed to update.")

            self.update_status(f"Status: {success_count} succeeded, {failure_count} failed")
            self.update_summary(f"Summary: {total_devices} devices processed")
            messagebox.showinfo(
                "Success",
                f"CSV processed and policy updated.\nFailed devices saved to 'failed_devices.txt'"
            )

            # Quit the app and relaunch it using subprocess
            self.root.quit()

            # Relaunch the application
            time.sleep(1)  # Adding a short delay to avoid immediate restart
            subprocess.Popen([sys.executable] + sys.argv)

        except Exception as e:
            logging.error(f"Error during CSV processing: {e}")
            self.update_status("Status: Error during processing")
            self.update_summary("Summary: 0 devices processed")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def hex_to_decimal(self, hex_value):
        try:
            return str(int(hex_value, 16))
        except ValueError:
            logging.warning(f"Invalid hex value encountered: {hex_value}. Defaulting to '0'.")
            return "0"

    def update_status(self, status):
        if self.status_label:
            self.status_label.config(text=status)

    def update_summary(self, count):
        if self.summary_label:
            self.summary_label.config(text=count)

    def on_policy_select(self, event=None):
        selected = self.selected_policy.get()
        if selected:
            self.process_button.config(state="normal")
            self.update_status(f"Status: Selected Policy - {selected}")
            self.update_summary("Summary: 0 devices processed")
        else:
            self.process_button.config(state="disabled")
            self.update_status("Status: No policy selected")
            self.update_summary("Summary: 0 devices processed")

    def select_csv_file(self):
        path = filedialog.askopenfilename(title="Select CSV File",
                                          filetypes=[("CSV Files", "*.csv")])
        if path:
            self.CSV_FILEPATH = path
            messagebox.showinfo("File Selected", f"Selected file: {path}")
            logging.info(f"CSV selected: {path}")
            self.update_status(f"Selected CSV: {os.path.basename(path)}")
            self.update_summary("0 devices processed")

    def process_csv_and_update_policy(self):
        if not self.CSV_FILEPATH:
            messagebox.showerror("Error", "No CSV file selected.")
            self.update_status("No CSV selected")
            self.update_summary("0 devices processed")
            return

        if not self.selected_policy.get():
            messagebox.showerror("Error", "No policy selected.")
            self.update_status("No policy selected")
            self.update_summary("0 devices processed")
            return

        pol = self.policy_id_mapping.get(self.selected_policy.get())
        if not pol:
            messagebox.showerror("Error", "Policy not found.")
            self.update_status("Policy not found")
            self.update_summary("0 devices processed")
            return

        threading.Thread(
            target=self._process_csv_and_update_policy_thread,
            args=(pol,),
            daemon=True
        ).start()

    def main_menu(self):
        self.clear_window()
        self.root.title("Cancom Device Control Tool")

        Label(self.root, text="Cancom Device Control Tool", font=("Segoe UI", 20, "bold"),
              bg=LIGHT_BG, fg=PRIMARY_RED).pack(pady=20)

        Button(self.root, text="Select CSV File", style="Rounded.TButton",
               command=self.select_csv_file).pack(pady=10)

        Label(self.root, text="Select Device Control Policy:", font=("Segoe UI", 12, "bold"),
              bg=LIGHT_BG, fg=DARK_GRAY).pack(pady=10)
        self.policy_dropdown = Combobox(self.root, textvariable=self.selected_policy,
                                        state="readonly", width=50, font=("Segoe UI", 12))
        self.policy_dropdown.pack(pady=5)
        self.policy_dropdown.bind("<<ComboboxSelected>>", self.on_policy_select)

        self.process_button = Button(
            self.root,
            text="Process CSV and Update Policy",
            style="RoundedBlue.TButton",
            command=self.process_csv_and_update_policy
        )
        self.process_button.pack(pady=20)
        self.process_button.config(state="disabled")

        self.status_label = Label(self.root, text="Status: Waiting for action",
                                  font=("Segoe UI", 12), bg=LIGHT_BG, fg=PRIMARY_RED)
        self.status_label.pack(pady=5)
        self.summary_label = Label(self.root, text="Summary: 0 devices processed",
                                   font=("Segoe UI", 12), bg=LIGHT_BG, fg=DARK_GRAY)
        self.summary_label.pack(pady=5)

        trademark_label = Label(self.root, text="© Benjamin Lettner",
                                font=("Segoe UI", 10), bg=LIGHT_BG, fg=DARK_GRAY)
        trademark_label.pack(side="bottom", anchor="se", padx=10, pady=10)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()


def main():
    root = Tk()
    app = DeviceControlApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
