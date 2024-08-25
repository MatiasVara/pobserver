use linux_personality::personality;
use nix::sys::ptrace;
use nix::sys::ptrace::AddressType;
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitStatus;
use nix::unistd::fork;
use nix::unistd::ForkResult;
use nix::unistd::Pid;
use std::ffi::CStr;
use std::ffi::CString;

pub struct Breakpoint {
    pub addr: u64,
    pub previous_word: i8,
}

pub struct Observer {
    breakpoints: Vec<Breakpoint>,
    path: &'static str,
    pid: Pid,
}

impl Observer {
    pub fn new(path: &'static str) -> Self {
        Observer {
            breakpoints: Vec::new(),
            path,
            pid: nix::unistd::Pid::from_raw(0),
        }
    }

    pub fn run(&mut self) {
        let fork_result = unsafe { fork() }.expect("Failed to fork");
        match fork_result {
            ForkResult::Parent { child } => {
                let _waitpid_result = waitpid(child, None).expect("Failed to wait");
                self.pid = child;
                return;
            }
            ForkResult::Child => {
                personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();
                ptrace::traceme().expect("Failed to call traceme in child");
                let path: &CStr = &CString::new(self.path).unwrap();
                nix::unistd::execve::<&CStr, &CStr>(path, &[], &[]).unwrap();
            }
        }
    }

    // add and install breakpoint
    pub fn add_breakpoint(&mut self, addr: u64) {
        // keep previous opcode
        let previous_word = ptrace::read(self.pid, addr as AddressType).expect("fail");
        let previous_word = (previous_word & 0xff) as i8;
        let bp = Breakpoint {
            addr,
            previous_word,
        };
        self.breakpoints.push(bp);
    }

    pub fn run_until_breakpoint(&self) -> u64 {
        loop {
            ptrace::step(self.pid, None).expect("failed");
            let _waitpid_result = waitpid(self.pid, None).expect("Failed to wait");

            // set all breakpoints
            for bp in self.breakpoints.iter() {
                let current_word =
                    ptrace::read(self.pid, bp.addr as AddressType).expect("Failed at read");
                let word_to_write = (current_word & !0xff) | 0xcc;
                unsafe {
                    let _ = ptrace::write(
                        self.pid,
                        bp.addr as AddressType,
                        word_to_write as AddressType,
                    );
                };
            }

            // run child until hits breakpoint
            ptrace::cont(self.pid, None).expect("Failed continue process");

            let wait_result = waitpid(self.pid, None).expect("Failed to wait");

            match wait_result {
                WaitStatus::Exited(child, status) => {
                    println!("Child {child} exited with status {status}, quitting...");
                    return 0;
                }
                // hit a breakpoint
                WaitStatus::Stopped(_child, Signal::SIGTRAP) => {
                    let mut regs = ptrace::getregs(self.pid).unwrap();
                    regs.rip = regs.rip - 1;
                    // remove current breakpoint
                    for bp in self.breakpoints.iter() {
                        if bp.addr == regs.rip {
                            let current_word =
                                ptrace::read(self.pid, bp.addr as AddressType).unwrap();
                            let word_to_write =
                                (current_word & !0xff) | (0xff & bp.previous_word as i64);
                            unsafe {
                                let _ = ptrace::write(
                                    self.pid,
                                    bp.addr as AddressType,
                                    word_to_write as AddressType,
                                );
                            };
                            break;
                        }
                    }
                    ptrace::setregs(self.pid, regs).unwrap();
                    return regs.rip;
                }
                _wait_status => {
                    continue;
                }
            }
        }
    }
}
