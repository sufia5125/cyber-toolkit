import socket   
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

while True:
    target = input ("Enter target IP address (ipv4): ").strip()
    
    try:
        ipaddress.ip_address(target)    #check if input is ipv4 or ipv6 format
        break
    except ValueError:
        print("Invalid IP address!!!")

start= 1
end = 1024

def port_scanner(target,port):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   #af_inet -> ipv4, sock_stream -> tcp
    my_socket.settimeout(0.2)
    
    result = my_socket.connect_ex((target, port))
    my_socket.close()
    
    if result == 0:
        return port
    return None


print("Scanning...please wait a little")
print("~"*35)
workers = 50

#multithreading 
with ThreadPoolExecutor(max_workers=workers) as executor:
    futures = [
        executor.submit(port_scanner, target, port)
        for port in range (start, end+1)
    ]
    
    for future in as_completed(futures):
        port = future.result()
        
        if port is not None:
            print(f"Port {port} is open!")
            
print("Scan done!")