#!/usr/bin/env python3
import socket, struct, sys, signal, selectors
import io, types
from typing import Dict, Optional
import threading
import queue

# --- Configuration (Same) ---
HOST = '0.0.0.0'
PORT = 443
XOR_KEY = 123
EXPECTED_TOKEN = b"LAB_TOKEN:v1"

# --- Global State for Session Management ---
sel = selectors.DefaultSelector()
sessions: Dict[int, types.SimpleNamespace] = {}
session_counter = 0
active_session_id: Optional[int] = None
input_queue = queue.Queue() # Queue for commands from input thread

# --- Utility Functions (Same) ---
def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])

def send_message(conn, data: bytes):
    """Sends a framed message (4-byte length + data)."""
    length = struct.pack('>I', len(data))
    conn.sendall(length + data)

# --- Helper function for prompt management ---
def refresh_prompt():
    """Prints the prompt, clearing the previous line."""
    prompt_text = f"Cmd (Session {active_session_id or 'none'} > ): "
    # Clear the current line (assuming a max width of 80)
    sys.stdout.write('\r' + ' ' * 80 + '\r') 
    sys.stdout.write(prompt_text)
    sys.stdout.flush()

# --- Client Handler Functions ---

def accept_wrapper(sock):
    """Handles a new incoming client connection."""
    global session_counter
    conn, addr = sock.accept()
    conn.setblocking(False)

    session_counter += 1
    session_id = session_counter

    session = types.SimpleNamespace(
        id=session_id,
        addr=addr,
        sock=conn,
        authenticated=False,
        recv_header=b'',
        recv_length=0,
        recv_buffer=b'',
        send_buffer=io.BytesIO()
    )

    sel.register(conn, selectors.EVENT_READ, data=session)
    sessions[session_id] = session

    # Use refresh_prompt after printing status messages
    print(f"\n[Srv] New connection from {addr}. Assigned Session ID: {session_id}")
    if not active_session_id:
        switch_session(session_id)
    else:
        print(f"[Srv] Current active session remains {active_session_id}.")
    
    print(f"[Srv] Waiting for token from Session {session_id}...")
    refresh_prompt()


def service_connection(key, mask):
    """Services I/O on a client socket."""
    sock = key.fileobj
    session = key.data

    try:
        if mask & selectors.EVENT_READ:
            data = sock.recv(4096)
            if data:
                process_received_data(session, data)
            else:
                print(f"\n[Srv] Closing connection for Session {session.id} ({session.addr}) - Client disconnected.")
                close_session(session)
    except Exception as e:
        print(f"\n[Srv] Error servicing Session {session.id} ({session.addr}): {e}")
        close_session(session)

def process_received_data(session, new_data: bytes):
    """Handles and reconstructs framed messages from incoming bytes."""
    data = new_data
    while data:
        if session.recv_length == 0:
            bytes_to_read = 4 - len(session.recv_header)
            chunk = data[:bytes_to_read]
            session.recv_header += chunk
            data = data[bytes_to_read:]

            if len(session.recv_header) == 4:
                session.recv_length = struct.unpack('>I', session.recv_header)[0]
                session.recv_header = b''

        if session.recv_length > 0:
            bytes_to_read = session.recv_length - len(session.recv_buffer)
            chunk = data[:bytes_to_read]
            session.recv_buffer += chunk
            data = data[bytes_to_read:]

            if len(session.recv_buffer) == session.recv_length:
                full_message = session.recv_buffer
                session.recv_length = 0
                session.recv_buffer = b''
                handle_message(session, full_message)

def handle_message(session, enc_message: bytes):
    """Decrypts and processes a full message from the client."""
    
    if not session.authenticated:
        token = xor_bytes(enc_message, XOR_KEY)
        if token != EXPECTED_TOKEN:
            print(f"\n[Auth] Session {session.id} Invalid token: {token}")
            send_message(session.sock, xor_bytes(b"AUTH_FAIL", XOR_KEY))
            close_session(session)
        else:
            session.authenticated = True
            send_message(session.sock, xor_bytes(b"AUTH_OK", XOR_KEY))
            print(f"\n[Auth] Session {session.id} ({session.addr}) authenticated.")
            refresh_prompt()
    
    else:
        try:
            resp = xor_bytes(enc_message, XOR_KEY).decode('utf-8', errors='ignore')
            
            # Print response clearly with session context
            print(f"\n--- Response from Session {session.id} ---")
            print(resp)
            print("-----------------------------------")
            refresh_prompt() # Refresh after printing the response

        except Exception as e:
            print(f"\n[Srv] Error decrypting or decoding response from Session {session.id}: {e}")
            close_session(session)


def close_session(session):
    """Closes the socket and removes the session from the selector/dictionary."""
    global active_session_id
    try:
        sel.unregister(session.sock)
    except KeyError:
        pass
        
    session.sock.close()
    del sessions[session.id]

    if active_session_id == session.id:
        print(f"[Srv] The active session {session.id} was closed.")
        if sessions:
            new_id = next(iter(sessions.keys()))
            switch_session(new_id)
        else:
            active_session_id = None
            print("[Srv] No active sessions remaining. Type 'list' or 'exit'.")
    
    refresh_prompt() # Refresh after session change/closure

# --- Server Management and CLI Functions ---

def switch_session(new_id: int):
    """Sets the given session ID as the active target for commands."""
    global active_session_id
    if new_id in sessions:
        active_session_id = new_id
        print(f"[Srv] Switched to active Session {new_id} ({sessions[new_id].addr}).")
    else:
        print(f"[Srv] Session ID {new_id} not found.")

def print_sessions():
    """Lists all currently active sessions."""
    print("\n--- Active Sessions ---")
    if not sessions:
        print("No active sessions.")
        return
    for s_id, session in sessions.items():
        auth_status = "OK" if session.authenticated else "Waiting for Token"
        active_marker = " <--" if s_id == active_session_id else ""
        print(f"[{s_id}]{active_marker}: {session.addr[0]}:{session.addr[1]} | Status: {auth_status}")
    print("-----------------------")

def handle_cli_input(cmd: str):
    """Processes server-side command line input from the queue."""
    cmd = cmd.strip()
    if not cmd:
        return

    parts = cmd.lower().split()
    
    if parts[0] == "exit":
        raise EOFError # Use exception to break the main loop

    elif parts[0] == "list":
        print_sessions()

    elif parts[0] == "switch":
        try:
            new_id = int(parts[1])
            switch_session(new_id)
        except (IndexError, ValueError):
            print("[Srv] Usage: switch <session_id>")
    
    elif active_session_id is not None and active_session_id in sessions:
        # Treat as a command to be sent to the active client
        session = sessions[active_session_id]
        
        # send XOR-encrypted framed command
        print(f"[Srv] Sending command to Session {active_session_id}: '{cmd}'")
        send_message(session.sock, xor_bytes(cmd.encode('utf-8'), XOR_KEY))
    
    else:
        print("[Srv] No active session selected. Use 'list' or 'switch <id>'.")

# --- THREADING FUNCTION ---
def read_cli_input(input_q):
    """Function run in a separate thread to handle blocking console input."""
    # Note: We do NOT print "Input thread started." here to keep output clean
    while True:
        try:
            cmd = input()
            input_q.put(cmd)
        except EOFError:
            input_q.put("exit")
            break
        except Exception:
            # Handle thread closing/other errors
            input_q.put("exit")
            break

# --- Main Server Execution ---

def signal_handler(sig, frame):
    """Graceful shutdown on SIGINT."""
    print("\n[Srv] Received SIGINT. Shutting down server.")
    input_queue.put("exit") # Signal input thread to stop
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

try:
    # 1. Setup Listening Socket
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((HOST, PORT))
    lsock.listen()
    lsock.setblocking(False)
    
    sel.register(lsock, selectors.EVENT_READ, data=None)

    # 2. Start the dedicated input thread
    input_thread = threading.Thread(target=read_cli_input, args=(input_queue,), daemon=True)
    input_thread.start()

    print(f"XOR server listening on {HOST}:{PORT}")
    print("Use 'list', 'switch <id>', or type a command to send to the active session.")
    
    # Print initial prompt
    refresh_prompt() 
    
    # 3. Main Event Loop
    while True:
        # Check for user input from the queue (non-blocking)
        try:
            cmd = input_queue.get_nowait()
            
            # Process command
            handle_cli_input(cmd)
            
            # If the command didn't raise EOFError (i.e., it wasn't 'exit'), refresh the prompt
            if cmd.lower().strip() != "exit":
                refresh_prompt()
                
        except queue.Empty:
            pass # No user input, continue to check sockets
        except EOFError: 
            break # Exit the main loop on "exit" command

        # Wait for socket events (non-blocking when queue check is active)
        # Timeout of 0.1s ensures the loop checks the input_queue regularly
        events = sel.select(timeout=0.1) 
        for key, mask in events:
            file_obj = key.fileobj
            
            if file_obj is lsock:
                accept_wrapper(lsock)
            else:
                service_connection(key, mask)
        
except KeyboardInterrupt:
    print("\n[Srv] Exiting main loop via Ctrl+C.")
finally:
    # Ensure the input thread is signaled to stop
    try:
        input_queue.put("exit")
    except:
        pass
        
    # Standard cleanup
    sel.close()
    lsock.close()
    print("[Srv] Server shut down.")