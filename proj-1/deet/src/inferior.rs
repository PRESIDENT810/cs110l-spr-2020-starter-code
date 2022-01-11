use crate::dwarf_data::DwarfData;
use crate::debugger::Breakpoint;

use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::process::Child;
use std::process::Command;
use std::os::unix::process::CommandExt;
use std::mem::size_of;
use std::collections::HashMap;


fn align_addr_to_word(addr: usize) -> usize {
    addr & (-(size_of::<usize>() as isize) as usize)
}

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

/// An inferior is a process that is being traced by the debugger
pub struct Inferior {
    child: Child,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>, breakpoint_map: &mut HashMap<usize, Breakpoint>) -> Option<Inferior> {
        // spawn a child process with PTRACE_TRACEME on
        let command = unsafe{ 
            Command::new(target)
            .args(args)
            .pre_exec(child_traceme)
            .spawn() 
        };     
        match command {
            Ok(_child) => {
                // wait for child process stopping with SIGTRAP
                let mut inferior = Inferior{child: _child};
                let status = inferior.wait(None);
                match status {
                    Ok(Status::Stopped(_signal, _usize)) => {
                        // set breakpoints
                        inferior.set_breakpoints(breakpoint_map);
                        return Some(inferior);
                    },
                    _ => return None,
                }
            },
            _ => {
                panic!("failed to spawn the child process");
            }
        };        
    }

    pub fn set_breakpoints(&mut self, breakpoint_map: &mut HashMap<usize, Breakpoint>) {
        for mut pair in breakpoint_map {
            let orig_byte = self.write_byte(*pair.0, 0xcc).expect("failed to write breakpoint");
            pair.1.orig_byte = orig_byte;
        }
    }

    pub fn set_breakpoint(&mut self, breakpoint: &mut Breakpoint) {
        let orig_byte = self.write_byte(breakpoint.addr, 0xcc).expect("failed to write breakpoint");
        breakpoint.orig_byte = orig_byte;
    }

    fn write_byte(&mut self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        let aligned_addr = align_addr_to_word(addr);
        // println!("writing val {:#x} to addr {:#x} ((aligned {}) ) with pid {}", val, addr, aligned_addr, self.pid());
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType).unwrap() as u64;
        // println!("original word: {:#x}", word);
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        // println!("updated word: {:#x}", updated_word);
        ptrace::write(
            self.pid(),
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        ).unwrap();
        Ok(orig_byte as u8)
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    // Calls cont on this inferior wake up inferior process, so it continues to execute
    pub fn cont(&mut self, breakpoint_map: &HashMap<usize, Breakpoint>) -> Result<Status, nix::Error> {
        // set rip = rip-1 to rewind the instruction pointer
        let last_rip = ptrace::getregs(self.pid()).expect("getregs failed").rip-1;   
        // println!("Continue from address: {:#x}", &last_rip);
        // if inferior is stopped at a breakpoint
        
        if breakpoint_map.get(&(last_rip as usize)).is_some() {
            // println!("breakpoint hit!");
            // remove breakpoint by restoring the first byte of the instruction we replaced
            let current_bp = breakpoint_map.get(&(last_rip as usize)).unwrap();
            self.write_byte(last_rip as usize, current_bp.orig_byte).expect("failed to remote breakpoint");
            
            let mut regs = ptrace::getregs(self.pid()).expect("getregs failed");
            regs.rip = last_rip;
            ptrace::setregs(self.pid(), regs);
            
            // step to the next instruction
            ptrace::step(self.pid(), None)?;
            self.wait(None);

            // restore the breakpoint
            self.write_byte(last_rip as usize, 0xcc).expect("failed to restore breakpoint");
        }

        // continue to resome normal execution
        match ptrace::cont(self.pid(), None){
            Ok(_) => self.wait(None),
            Err(e) => panic!("ptrace cont failed: {:?}", e),
        }
    }

    pub fn kill(&mut self) -> Result<(), std::io::Error>{
        match self.child.kill(){
            Ok(_) => {
                self.wait(None); // leave no zombie process!
                return Ok(());
            },
            Err(e) => Err(e),
        }
    }

    pub fn print_backtrace(&self, debug_data: &DwarfData) -> Result<(), nix::Error>{
        let regs = ptrace::getregs(self.pid()).expect("getregs failed");   
        let mut rip = regs.rip as usize;
        let mut rbp = regs.rbp as usize;
        // println!("%rip register: {:#x}", &regs.rip);
        
        loop{
            let line = debug_data.get_line_from_addr(rip);
            let func = debug_data.get_function_from_addr(rip);
            
            if line.is_none() || func.is_none() {
                panic!("no line or function found");
            } else{
                let line = line.as_ref().unwrap();
                let func = func.as_ref().unwrap();
                println!("{} ({}:{})", func, line.file, line.number);
                if func == "main"{
                    break;
                }
                match ptrace::read(self.pid(), (rbp+8) as ptrace::AddressType){
                    Ok(addr) => {
                        rip = addr as usize;
                    },
                    Err(e) => panic!("read failed: {:?}", e),
                }
                match ptrace::read(self.pid(), (rbp) as ptrace::AddressType){
                    Ok(addr) => {
                        rbp = addr as usize;
                    },
                    Err(e) => panic!("read failed: {:?}", e),
                }
            }
        }

        return Ok(());
    }
}
