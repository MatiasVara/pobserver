use crate::ptrace::AddressType;
use linux_personality::personality;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitStatus;
use nix::unistd::{fork, ForkResult};
use std::ffi::CStr;
use std::ffi::CString;

pub struct Breakpoint {
    pub addr: u64,
    pub previous_value: i8,
}

fn main() {
    // Get addr from the name of the functions
    let mut breakpoints = vec![
        Breakpoint {
            addr: 0x55555555b8a0,
            previous_value: 0,
        },
        Breakpoint {
            addr: 0x55555555b890,
            previous_value: 0,
        },
    ];

    let fork_result = unsafe { fork() }.expect("Failed to fork");
    match fork_result {
        ForkResult::Parent { child } => {
            let _waitpid_result = waitpid(child, None).expect("Failed to wait");

            // read data without the breakpoint
            for bp in breakpoints.iter_mut() {
                let previous_word = ptrace::read(child, bp.addr as AddressType).expect("fail");
                bp.previous_value = (previous_word & 0xff) as i8;
            }

            loop {
                ptrace::step(child, None).expect("failed");
                let _waitpid_result = waitpid(child, None).expect("Failed to wait");

                // set all breakpoints
                for bp in breakpoints.iter() {
                    let current_word =
                        ptrace::read(child, bp.addr as AddressType).expect("Failed at read");
                    let word_to_write = (current_word & !0xff) | 0xcc;
                    unsafe {
                        let _ = ptrace::write(
                            child,
                            bp.addr as AddressType,
                            word_to_write as AddressType,
                        );
                    };
                }

                // run child until hits int 3
                ptrace::cont(child, None).expect("Failed continue process");

                let wait_result = waitpid(child, None).expect("Failed to wait");

                match wait_result {
                    WaitStatus::Exited(child, status) => {
                        println!("Child {child} exited with status {status}, quitting...");
                        break;
                    }
                    WaitStatus::Stopped(_child, Signal::SIGTRAP) => {
                        let mut regs = ptrace::getregs(child).unwrap();
                        regs.rip = regs.rip - 1;
                        println!("Hit breakpoint at 0x{:x}", regs.rip);
                        // remove last breakpoint
                        for bp in breakpoints.iter() {
                            if bp.addr == regs.rip {
                                let current_word =
                                    ptrace::read(child, bp.addr as AddressType).unwrap();
                                let word_to_write =
                                    (current_word & !0xff) | (0xff & bp.previous_value as i64);
                                unsafe {
                                    let _ = ptrace::write(
                                        child,
                                        bp.addr as AddressType,
                                        word_to_write as AddressType,
                                    );
                                };
                                break;
                            }
                        }
                        ptrace::setregs(child, regs).unwrap();
                    }
                    wait_status => {
                        println!("{wait_status:?}");
                        continue;
                    }
                }
            }
        }
        ForkResult::Child => {
            personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();
            ptrace::traceme().expect("Failed to call traceme in child");
            let path: &CStr = &CString::new("../debugee/target/debug/debugee").unwrap();
            nix::unistd::execve::<&CStr, &CStr>(path, &[], &[]).unwrap();
        }
    }
}
