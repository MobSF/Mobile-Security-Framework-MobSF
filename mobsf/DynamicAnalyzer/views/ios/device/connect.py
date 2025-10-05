# -*- coding: utf_8 -*-
"""Connect to iOS device using SSH over USB or WiFi."""

import logging
import paramiko
import socket
import time
import subprocess
import threading

from mobsf.DynamicAnalyzer.views.ios.helpers import (
    get_ios_model_mapping,
)

logger = logging.getLogger(__name__)


class IOSConnector:
    """Connect to iOS device using SSH over USB or WiFi."""

    def __init__(self):
        """Initialize the IOSConnector."""
        self.ssh_client = None
        self.connection_type = None
        self.device_info = {}
        self.host = None
        self.port = None
        self.username = None
        self.password = None

    def _ssh_execute_command(self, command, timeout=30):
        """Execute a command on SSH client."""
        if not self.ssh_client:
            return None, None, None
        
        # Shared variables for thread communication
        result = {'output': '', 'error': '', 'exit_status': -1, 'exception': None, 'channel': None}
        command_completed = threading.Event()
        
        def execute_command():
            """Execute command in separate thread."""
            try:
                # Execute command
                _, stdout, stderr = self.ssh_client.exec_command(command)
                channel = stdout.channel
                result['channel'] = channel
                
                # Read output with partial capture
                output_parts = []
                error_parts = []
                
                # Read stdout in chunks to capture partial output
                while True:
                    try:
                        chunk = stdout.read(1024).decode('utf-8', errors='ignore')
                        if not chunk:
                            break
                        output_parts.append(chunk)
                    except Exception:
                        break
                
                # Read stderr in chunks to capture partial output
                while True:
                    try:
                        chunk = stderr.read(1024).decode('utf-8', errors='ignore')
                        if not chunk:
                            break
                        error_parts.append(chunk)
                    except Exception:
                        break
                
                result['output'] = ''.join(output_parts).strip()
                result['error'] = ''.join(error_parts).strip()
                
                # Try to get exit status if available
                try:
                    result['exit_status'] = channel.recv_exit_status()
                except Exception:
                    result['exit_status'] = -1
                
            except Exception as e:
                result['exception'] = e
            finally:
                command_completed.set()
        
        # Start command execution in separate thread
        command_thread = threading.Thread(target=execute_command, daemon=True)
        command_thread.start()
        
        # Wait for command to complete or timeout
        if command_completed.wait(timeout=timeout):
            if result['exception']:
                logger.error("Command execution failed: %s", str(result['exception']))
                return result['output'], result['error'], -1
            return result['output'], result['error'], result['exit_status']
        else:
            if "oslog" not in command:
                logger.warning("Command execution timed out after %d seconds: %s", timeout, command)
            
            # Try to close the channel if it exists
            if result['channel']:
                try:
                    result['channel'].close()
                except Exception:
                    pass
            
            # Return any partial output that was captured
            return result['output'], result['error'], -1

    def connect_usb(self, device_id=None, username='root', password='alpine', port=2222):
        """Connect to iOS device using USB (via usbmuxd/iproxy)."""
        try:
            logger.info("Attempting USB connection to iOS device via SSH")
            
            # Check if usbmuxd/iproxy is available
            if not self._check_usbmuxd():
                raise Exception("usbmuxd/iproxy not available. Install libimobiledevice.")
            
            # Find USB connected iOS devices
            devices = self.get_usb_devices()
            if not devices:
                raise Exception("No USB connected iOS devices found")
            
            # List all devices
            logger.info("Available USB devices:")
            for device in devices:
                logger.info(
                    "Device:\n"
                    "  ID:      %s\n"
                    "  Name:    %s\n"
                    "  Model:   %s\n"
                    "  Version: %s\n"
                    "  Serial:  %s",
                    device.get('id', 'Unknown'),
                    device.get('name', 'Unknown'),
                    device.get('model', 'Unknown'),
                    device.get('version', 'Unknown'),
                    device.get('serial', 'Unknown')
                )
            
            # Use specified device or first available
            if device_id:
                device = next((d for d in devices if d['id'] == device_id), None)
                if not device:
                    raise Exception("Device %s not found" % device_id)
            else:
                device = devices[0]
            
            logger.info(
                "Selected device:\n"
                "  ID:      %s\n"
                "  Name:    %s\n"
                "  Model:   %s\n"
                "  Version: %s\n"
                "  Serial:  %s",
                device.get('id', 'Unknown'),
                device.get('name', 'Unknown'),
                device.get('model', 'Unknown'),
                device.get('version', 'Unknown'),
                device.get('serial', 'Unknown')
            )
            
            # Setup port forwarding using iproxy
            self._setup_usb_port_forward(device['id'], port)
            
            # Prepare device info
            device_info = {
                'id': device['id'],
                'name': device['name'],
                'type': 'usb',
                'connection': f'localhost:{port}'
            }
            
            # Establish SSH connection
            self._establish_ssh_connection('localhost', port, username, password, 'usb', device_info)
            
            logger.info("Successfully connected to %s via USB SSH", device['name'])
            return True
            
        except Exception as e:
            logger.error("USB connection failed: %s", str(e))
            return False

    def connect_wifi(self, ip_address, port=22, username='root', password='alpine'):
        """Connect to iOS device using WiFi SSH."""
        try:
            if port not in range(1, 65535):
                raise Exception("Invalid port number")
            logger.info("Attempting WiFi SSH connection to %s:%s", ip_address, port)
            
            # Prepare device info
            device_info = {
                'ip': ip_address,
                'port': port,
                'type': 'wifi',
                'connection': f'{ip_address}:{port}'
            }
            
            # Establish SSH connection
            self._establish_ssh_connection(ip_address, port, username, password, 'wifi', device_info)
            return True
        except Exception as e:
            logger.error("WiFi connection failed: %s", str(e))
            return False
    
    def disconnect(self):
        """Disconnect from iOS device."""
        try:
            if self.ssh_client:
                self.ssh_client.close()
                self.ssh_client = None
            
            if self.connection_type == 'usb':
                subprocess.run(['pkill', '-f', 'iproxy'], 
                             capture_output=True)
            logger.info("Disconnected from iOS device")
        except Exception as e:
            logger.error("Error during disconnect: %s", str(e))
        finally:
            if hasattr(self, 'ssh_client') and self.ssh_client:
                try:
                    self.ssh_client.close()
                except Exception:
                    pass
            self.ssh_client = None
            self.connection_type = None
            self.device_info = {}
            self.host = None
            self.port = None
            self.username = None
            self.password = None

    def get_usb_devices(self):
        """Get list of USB connected iOS devices."""
        try:
            logger.info("Getting iOS devices connected via USB")
            # Use idevice_id to list devices
            result = subprocess.run(['idevice_id', '-l'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                return []
            
            devices = []
            model_mapping = get_ios_model_mapping()
            for device_id in result.stdout.strip().split('\n'):
                if device_id:
                    device_info = {}
                    # Get device details
                    output = subprocess.run(['ideviceinfo', '-u', device_id], 
                                               capture_output=True, text=True)
                    if output.returncode != 0:
                        continue
                    for line in output.stdout.splitlines():
                        if ": " in line:
                            key, value = line.split(": ", 1)
                            device_info[key.strip()] = value.strip()
                  
                    devices.append({
                        'id': device_id,
                        'name': device_info.get("DeviceName"),
                        'model': model_mapping.get(device_info.get("ProductType"), device_info.get("ProductType")),
                        'version': device_info.get("ProductVersion"),
                        'serial': device_info.get("SerialNumber"),
                    })

            return devices
        except Exception as e:
            logger.error("Failed to get USB devices: %s", str(e))
            return []       

    def _create_ssh_connection(self, host, port, username, password, timeout=10):
        """Create and connect an SSH client."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        return ssh

    def _test_connection_ssh(self, host, port=22, username='root', password='alpine', timeout=10):
        """Test SSH connection to iOS device."""
        try:
            logger.info("Testing SSH connection to %s:%s", host, port)
            
            # Create SSH client
            ssh = self._create_ssh_connection(host, port, username, password, timeout)
            
            # Temporarily set self.ssh_client to test client
            self.ssh_client = ssh
            
            # Test basic command execution - check user identity
            output, _, _ = self._ssh_execute_command('id', timeout)
            
            # Check if we have root access
            if 'uid=0(root)' in output:
                logger.info('Verified iOS device is Jailbroken')
                return True
            else:
                logger.warning("Not connected as root: %s", output)
                return False
            
        except Exception as e:
            logger.error("SSH connection test failed: %s", str(e))
            return False

    def _establish_ssh_connection(self, host, port, username, password, connection_type, device_info):
        """Establish SSH connection and set up instance variables."""
        # Test SSH connection first
        if not self._test_connection_ssh(host, port, username, password):
            raise Exception("SSH connection test failed")
        
        # Establish SSH connection
        if not self.ssh_client:
            self.ssh_client = self._create_ssh_connection(host, port, username, password)
        
        # Set up instance variables
        self.connection_type = connection_type
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.device_info = device_info
        
        logger.info("Successfully established SSH connection to %s:%s", host, port)
        return True

    def _check_usbmuxd(self):
        """Check if usbmuxd/iproxy is available."""
        try:
            result = subprocess.run(['which', 'iproxy'], 
                                    capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False

    def _setup_usb_port_forward(self, device_id, port):
        """Setup port forwarding for USB device."""
        try:
            # Test if ports are open with separate sockets
            def test_port(port_to_test):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex(('localhost', port_to_test))
                    sock.close()
                    return result == 0
                except Exception:
                    return False
            
            # Check if port forwarding already exists
            ssh_port_open = test_port(port)
            frida_port_open = test_port(37042)
            
            if ssh_port_open and frida_port_open:
                logger.info("Port forwarding already exists: localhost:%s -> device:22, localhost:37042 -> device:27042", port)
                return True
            
            # Port forwarding doesn't exist, so set it up
            logger.info("Setting up new port forwarding for device %s", device_id)
            # Kill any existing iproxy processes for this device (in case they're stuck)
            subprocess.run(['pkill', '-f', f'iproxy.*{device_id}'], 
                         capture_output=True)
            time.sleep(1)
            
            # Start iproxy for port forwarding
            cmds = [['iproxy', str(port), '22', '-u', device_id],
                    ['iproxy', '37042', '27042', '-u', device_id]]
            for cmd in cmds:
                logger.info("Starting iproxy: %s", ' '.join(cmd))
                subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for port forwarding to be ready
            logger.info("Waiting for port forwarding to be ready...")
            time.sleep(2)  # Give iproxy time to establish connections
            
            # Test if ports are now open
            ssh_port_open = test_port(port)
            frida_port_open = test_port(37042)
            
            if not ssh_port_open or not frida_port_open:
                failed_ports = []
                if not ssh_port_open:
                    failed_ports.append(f"SSH port {port}")
                if not frida_port_open:
                    failed_ports.append("Frida port 37042")
                raise Exception(f"Port forwarding failed for: {', '.join(failed_ports)}")
            
            logger.info("Port forwarding established: localhost:%s -> device:22, localhost:37042 -> device:27042", port)
            return True
            
        except Exception as e:
            logger.error("Failed to setup USB port forwarding: %s", str(e))
            return False
