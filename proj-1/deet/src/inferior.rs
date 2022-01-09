use crate::dwarf_data::DwarfData;

use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::process::Child;
use std::process::Command;
use std::os::unix::process::CommandExt;

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
    pub fn new(target: &str, args: &Vec<String>) -> Option<Inferior> {
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
                let inferior = Inferior{child: _child};
                let status = inferior.wait(None);
                match status {
                    Ok(Status::Stopped(_signal, _usize)) => {
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
    pub fn cont(&self) -> Result<Status, nix::Error> {
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
