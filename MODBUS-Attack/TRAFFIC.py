from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient("192.168.10.107", port=503)
client.connect()

try:
  while True:

    print("Reading Input Registers (FC4 - Actuators)")
    rr1 = client.read_input_registers(address=0, count=2)

    if not rr1.isError():
        print("Input Registers:", rr1.registers)

    print("Reading Holding Registers (FC3 - Sensors)")
    rr2 = client.read_holding_registers(address=0, count=2)

    if not rr2.isError():
        print("Holding Registers:", rr2.registers)


    time.sleep(0.5)

except KeyboardInterrupt:
    print("Stopping traffic generation")

finally:
    client.close()
    print("Client connection closed")


