# 파일명: run_analyzer.py (최종 버전)
import frida
import sys
import os
import requests
import time
import configparser
import logging
import queue
import threading
from db_manager import DatabaseManager

# --- 로깅 설정 ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("analysis.log", encoding='utf-8'),
                        logging.StreamHandler()
                    ])

# --- 업로드 작업 큐 생성 ---
upload_queue = queue.Queue()

def upload_worker(mobsf_client, db_manager):
    while True:
        try:
            job_id, filepath, source_hook = upload_queue.get()
            logging.info(f"[Worker] Processing job for: {os.path.basename(filepath)}")
            upload_success = False
            for i in range(3):
                tags = f"job_{job_id},{source_hook}"
                result = mobsf_client.upload_file(filepath, tags=tags)
                if result:
                    scan_hash = result.get('hash')
                    db_manager.update_scan_hash(filepath, scan_hash)
                    upload_success = True
                    break
                else:
                    logging.warning(f"[Worker] Upload failed for {filepath}, retrying ({i+1}/3)...")
                    time.sleep(5)
            if not upload_success:
                logging.error(f"[Worker] Upload failed for {filepath} after 3 retries.")
            upload_queue.task_done()
        except Exception as e:
            logging.error(f"[Worker] An unhandled exception occurred: {e}")

class MobSFClient:
    def __init__(self, url, api_key):
        self.url = f"{url}/api/v1/upload"
        self.headers = {'Authorization': api_key}
    def upload_file(self, filepath, scan_type='dex', tags=None):
        if not os.path.exists(filepath):
            logging.error(f"File not found for upload: {filepath}")
            return None
        logging.info(f"Uploading {os.path.basename(filepath)} to MobSF (Type: {scan_type})...")
        try:
            with open(filepath, 'rb') as f:
                files = {'file': f}
                data = {'scan_type': scan_type}
                if tags:
                    data['tags'] = tags
                response = requests.post(self.url, headers=self.headers, files=files, data=data, timeout=120)
                response.raise_for_status()
            result = response.json()
            logging.info(f"MobSF Upload successful! Scan Hash: {result.get('hash')}")
            return result
        except requests.exceptions.RequestException as e:
            logging.error(f"MobSF upload failed: {e}")
            return None

class FridaAgent:
    def __init__(self, script_path, on_message_callback):
        self.script_path = script_path
        self.on_message_callback = on_message_callback
        self.session = None
        
    def start(self, device, package_name):
        logging.info(f"Spawning and attaching to {package_name}...")
        try:
            pid = device.spawn([package_name])
            self.session = device.attach(pid)
            
            with open(self.script_path, "r", encoding="utf-8") as f:
                script_code = f.read()
            script = self.session.create_script(script_code)
            script.on('message', self.on_message_callback)
            script.load()
            
            device.resume(pid)
            return script
        except Exception as e:
            logging.error(f"Unexpected error in Frida agent: {e}")
            return None

class AnalysisManager:
    def __init__(self, config_path='config.ini'):
        config = configparser.ConfigParser()
        config.read(config_path, encoding='utf-8')
        self.dump_dir = config.get('Settings', 'dump_dir')
        self.frida_script_path = config.get('Settings', 'frida_script_path')
        self.db_manager = DatabaseManager(config.get('Settings', 'db_path'))
        self.mobsf_client = MobSFClient(config.get('MobSF', 'url'), config.get('MobSF', 'api_key'))
        self.current_job_id = None
        self.target_package = None
    def on_frida_message(self, message, data):
        if message.get('type') == 'error':
            logging.error(f"Frida script error: {message.get('description', 'No description')}")
            return
        if message.get('type') == 'send' and data:
            metadata = message.get('payload', {})
            if metadata.get("type") == "DEX_DUMP":
                source = metadata.get('source', 'UnknownSource')
                target_dir = os.path.join(self.dump_dir, self.target_package)
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir)
                filename = f"{source}_{int(time.time())}.dex"
                filepath = os.path.join(target_dir, filename)
                try:
                    with open(filepath, 'wb') as f:
                        f.write(data)
                    logging.info(f"DEX file dumped to {filepath} ({len(data)} bytes)")
                    self.db_manager.log_dumped_file(self.current_job_id, filepath, source)
                    upload_queue.put((self.current_job_id, filepath, source))
                except Exception as e:
                    logging.error(f"Failed to save file: {filepath}, Error: {e}")
    def run_analysis(self, package_name):
        self.target_package = package_name
        self.current_job_id = self.db_manager.create_job(package_name)
        logging.info(f"Starting analysis for {package_name} (Job ID: {self.current_job_id})")
        self.db_manager.update_job_status(self.current_job_id, 'running')
        try:
            device = frida.get_usb_device(timeout=10)
            agent = FridaAgent(self.frida_script_path, self.on_frida_message)
            script = agent.start(device, package_name)
            if script:
                logging.info("Frida script loaded. Initializing hooks via RPC...")
                script.exports.initialize_hooks()
                logging.info("Analysis running... Press Ctrl+C to stop.")
                sys.stdin.read()
            self.db_manager.update_job_status(self.current_job_id, 'completed')
            logging.info(f"Analysis for Job ID {self.current_job_id} completed.")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            self.db_manager.update_job_status(self.current_job_id, 'error')
        finally:
            if 'agent' in locals() and agent.session:
                agent.session.detach()
            logging.info("Waiting for all uploads to complete...")
            upload_queue.join()
            logging.info("All uploads finished.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} [package_name]")
        print("Example: python run_analyzer.py owasp.mstg.uncrackable1")
        sys.exit(1)
    target_app_package = sys.argv[1]
    if not os.path.exists('config.ini'):
        logging.error("Error: 'config.ini' not found. Please create it.")
        sys.exit(1)
    manager = AnalysisManager()
    worker_thread = threading.Thread(target=upload_worker, args=(manager.mobsf_client, manager.db_manager), daemon=True)
    worker_thread.start()
    logging.info("Upload worker thread started.")
    manager.run_analysis(target_app_package)
