use std::fmt::Write;

// binary file parsing
extern crate bingrep;
use bingrep::Container;
use bingrep::parser::pe::PeFile;

extern crate capstone;
use self::capstone::prelude::*;
use self::capstone::arch::x86::X86OperandType;
use capstone::arch::ArchOperand;

// XXX: Write code to handle 64 bits
fn resolve_hal4(filename : &str) -> Option<u64> {
    println! ("Parsing {}", filename);
    let mut pe_file = PeFile::parse_file(filename);

    let base_addr = match pe_file.base() {
        Some (v) => v,
        None => return None,
    };

    println! ("hal.dll base         : 0x{:x}", base_addr);

    let addr_hal_init_system = pe_file.resolve("HalInitSystem");
    println! ("HalInitSystem RVA    : 0x{:x}", addr_hal_init_system);

    let s_name = pe_file.unresolve(addr_hal_init_system);

    let mut bytecode : [ u8; 512 ] = [ 0; 512 ];
    pe_file.read(base_addr + addr_hal_init_system, &mut bytecode);

    let cs_handle;
    
    if pe_file.is_32bits() {
        cs_handle = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();
    }
    else {
        cs_handle = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build();
    }

    let cs_handle = match cs_handle {
        Ok (v) => {
            v
        },
        Err (e) => {
            eprintln! ("Error: {}", e);
            panic! ("Bye");
        }
    };

    // search for HalpSystem
    println! ("[+] Looking up for HalpInitSystem");
    let mut found_halp = false;
    let mut idx = 0;
    let mut addr_dis = addr_hal_init_system;
    let mut line = String::with_capacity(64);
    let mut got_jmp = false;
    let mut HalpInitSystem = 0;
    while idx < bytecode.len() {
        let insns = match cs_handle.disasm_count(&bytecode[idx..], addr_dis, 1) {
            Ok (insns) => {
                insns
            },
            Err (e) => {
                return None;
            },
        };

        let mut iter_insn = insns.iter();
        let insn = match iter_insn.next() {
            Some (v) => v,
            None => return None,
        };

        line.write_fmt(format_args!("0x{:08x} : ", addr_dis));

        if let Some(mnemonic) = insn.mnemonic() {
            line.write_fmt(format_args!("{}", mnemonic));
        }
        if let Some(op_str) = insn.op_str() {
            line.write_fmt(format_args!(" {}", op_str));
        }
        //println! ("{}", line);

        if let Some(mnemonic) = insn.mnemonic() {
            if mnemonic == "jmp" {
                got_jmp = true;
            }
        }

        if got_jmp {
            let detail = cs_handle.insn_detail(&insn).expect("Could not get detail");
            let arch_detail = detail.arch_detail();
            let arch_ops = arch_detail.operands();

            for op in arch_ops {
                //println! ("op: {:?}", op);
                let operand = match op {
                    ArchOperand::X86Operand(myop) => {
                        myop
                    },
                    _ => continue,
                };

                match operand.op_type {
                    X86OperandType::Imm(value) => {
                        found_halp = true;
                        HalpInitSystem = base_addr + value as u64;
                        break;
                    },
                    _ => break,
                }
            }

            // stop disas if no halp
            break;
        }

        idx += insn.bytes().len();
        addr_dis += insn.bytes().len() as u64;
        line.clear();
    }

    if found_halp == false {
        println! ("Failed finding HalpInitSystem");
        return None;
    }

    println! ("-> HalpInitSystem : 0x{:x}", HalpInitSystem - base_addr);

    println! ("[+] Looking up for HaliQuerySystemInformation");

    pe_file.read(HalpInitSystem, &mut bytecode);

    idx = 0;
    addr_dis = HalpInitSystem;
    line.clear();
    got_jmp = false;
    let mut found_dispatch = false;
    let mut found_insn = false;
    let mut HaliQuerySystemInformation = None;
    let off_hal_4;
    if pe_file.is_32bits() {
        off_hal_4 = 4;
    }
    else {
        off_hal_4 = 16;
    }

    while idx < bytecode.len() {
        let insns = match cs_handle.disasm_count(&bytecode[idx..], addr_dis, 1) {
            Ok (insns) => {
                insns
            },
            Err (e) => {
                return None;
            },
        };

        let mut iter_insn = insns.iter();
        let insn = match iter_insn.next() {
            Some (v) => v,
            None => return None,
        };

        line.write_fmt(format_args!("0x{:08x} : ", addr_dis));

        if let Some(mnemonic) = insn.mnemonic() {
            line.write_fmt(format_args!("{}", mnemonic));
        }
        if let Some(op_str) = insn.op_str() {
            line.write_fmt(format_args!(" {}", op_str));
        }
        //println! ("{}", line);

        if let Some(mnemonic) = insn.mnemonic() {
            if mnemonic == "mov" {
                got_jmp = true;
            }
        }

        if got_jmp {
            let detail = cs_handle.insn_detail(&insn).expect("Could not get detail");
            let arch_detail = detail.arch_detail();
            let arch_ops = arch_detail.operands();

            for op in arch_ops {
                let operand = match op {
                    ArchOperand::X86Operand(myop) => {
                        myop
                    },
                    _ => continue,
                };

                match operand.op_type {
                    X86OperandType::Mem(op_mem) => {
                        // check that we got the HalDispatchTable
                        if op_mem.disp() as u64 == base_addr + pe_file.i_resolve("HalDispatchTable") {
                            //println! ("Got dispatch table");
                            found_dispatch = true;
                        }
                        // now check that we're trying to patch the HalDispatchTable+4
                        if found_dispatch && op_mem.disp() == off_hal_4 {
                            found_insn = true;
                        }
                    },
                    X86OperandType::Imm(v) => {
                        //if found_insn {
                        if found_insn {
                            HaliQuerySystemInformation = Some (v as u64 - base_addr);
                            break;
                        }
                    },
                    _ => continue,
                }
            }

            // we found it
            if let Some (success) = HaliQuerySystemInformation {
                break;
            }

            got_jmp = false;
        }

        idx += insn.bytes().len();
        addr_dis += insn.bytes().len() as u64;
        line.clear();
    }
    
    HaliQuerySystemInformation
}

fn main() {
    let HaliQuerySystemInformation = match resolve_hal4("hal.dll") {
        Some (v) => v,
        None => {
            eprintln! ("Failed resolving HaliQuerySystemInformation");
            return;
        },
    };
    println! ("-> HaliQuerySystemInformation : 0x{:x}", HaliQuerySystemInformation);
}

