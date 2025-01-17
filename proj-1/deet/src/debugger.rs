use crate::debugger_command::DebuggerCommand;
use crate::inferior::Inferior;
use crate::inferior::Status;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use rustyline::error::ReadlineError;
use nix::sys::ptrace;
use rustyline::Editor;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Breakpoint{
    pub addr: usize,
    pub orig_byte: u8,
}

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,
    breakpoint_map: HashMap<usize, Breakpoint>,
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        // initialize the DwarfData
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                panic!("Could not open file {}", target);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                panic!("Could not debugging symbols from {}: {:?}", target, err);
            }
        };

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            debug_data,
            breakpoint_map: HashMap::new(),
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                // handle run commmand
                DebuggerCommand::Run(args) => {
                    // before we run a new inferio, kill existing inferiors if any
                    if self.inferior.is_some() {
                        println!("Killing running inferior (pid {})", self.inferior.as_ref().unwrap().pid());
                        self.inferior.as_mut().unwrap().kill();
                    }
                    if let Some(inferior) = Inferior::new(&self.target, &args, &mut self.breakpoint_map) {
                        // Create the inferior
                        self.inferior = Some(inferior);
                        match self.inferior.as_mut().unwrap().cont(&self.breakpoint_map){
                            Ok(status) => self.handle_status(status),
                            Err(err) => panic!("{}", err),
                        }
                    } else {
                        println!("Error starting subprocess");
                    }
                },
                // handle quit command
                DebuggerCommand::Quit => {
                    if self.inferior.is_some() {
                        println!("Killing running inferior (pid {})", self.inferior.as_ref().unwrap().pid());
                        self.inferior.as_mut().unwrap().kill();
                    }
                    return;
                },
                // handle continue command
                DebuggerCommand::Continue => {
                    if self.inferior.is_none(){
                        println!("No inferior to continue");
                    } else {
                        match self.inferior.as_mut().unwrap().cont(&self.breakpoint_map){
                            Ok(status) => self.handle_status(status),
                            Err(err) => panic!("{}", err),
                        }
                    }
                },
                // handle backtrace command
                DebuggerCommand::Backtrace => {
                    if self.inferior.is_none(){
                        println!("No inferior to backtrace");
                    } else{
                        match self.inferior.as_ref().unwrap().print_backtrace(&self.debug_data){
                            Ok(_) => {},
                            Err(err) => panic!("{}", err),
                        }
                    }
                },
                // handle breakpoint command
                DebuggerCommand::Breakpoint(mut addr_str) => {
                    let addr = {
                        if &addr_str[0..1] == "*"{ // memory breakpoint
                            addr_str.remove(0);
                            parse_address(addr_str.as_str())
                        } else {
                            let parsed = parse_address(addr_str.as_str());
                            match parsed {
                                // TODO: implement breakpoint support for multiple files
                                Some(line) => self.debug_data.get_addr_for_line(None, line),
                                None => self.debug_data.get_addr_for_function(None, addr_str.as_str()),
                            }
                        }
                    };
                    // memory breakpoint
                    match addr {
                        Some(addr) => {
                            println!("Set breakpoint {} at {:#x}", self.breakpoint_map.len(), addr);
                            let mut breakpoint = Breakpoint{addr: addr, orig_byte: 0};
                            if self.inferior.is_some(){
                                self.inferior.as_mut().unwrap().set_breakpoint(&mut breakpoint);
                            }
                            self.breakpoint_map.insert(addr, breakpoint);
                        },
                        None => println!("Cannot set breakpoint at {}", addr_str),
                    };

                }
            }
        }
    }

    fn handle_status(&self, status: Status) {
        let rip = ptrace::getregs(self.inferior.as_ref().unwrap().pid()).expect("getregs failed").rip as usize;   
        // println!("stopped at addr {:#x}", &rip);
        match status{
            Status::Stopped(signal, _usize) => {
                println!("Child stopped (signal {})", signal);
                let rip = _usize;
                let line = self.debug_data.get_line_from_addr(rip);
                let func = self.debug_data.get_function_from_addr(rip);
                if line.is_none() || func.is_none() {
                    panic!("no line or function found");
                } else{
                    let line = line.as_ref().unwrap();
                    let func = func.as_ref().unwrap();
                    println!("Stopped at {}:{}", line.file, line.number);
                }
            },
            Status::Exited(exit_code) => {
                println!("Child exited (status {})", exit_code);
            },
            Status::Signaled(_signal) => {
                println!("Inferior exited due to signal");
            },
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}

fn parse_address(addr: &str) -> Option<usize> {
    if addr.to_lowercase().starts_with("0x") {
        let addr_without_0x = &addr[2..];
        return usize::from_str_radix(addr_without_0x, 16).ok();
    } else {
        let addr_without_0x = &addr;
        return usize::from_str_radix(addr_without_0x, 10).ok();
    };
}
