use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use crate::inferior::Inferior;
use crate::inferior::Status;
use crate::inferior::set_brk;
use rustyline::error::ReadlineError;
use rustyline::Editor;

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,

    brk_lists: Vec<usize>,
    brk_num: usize,
}

fn cont_inferior(debug_data: &DwarfData, inf: &mut Inferior) {
    match inf.continue_exec() {
        Ok(status) => {
            match status {
                Status::Exited(s) => println!("Child exited (status {})", s),
                Status::Signaled(sig) => println!("Child signaled with {}", sig),
                Status::Stopped(sig, rip) => {
                    println!("Child stopped (signal {})", sig);
                    if let Some(line) = debug_data.get_line_from_addr(rip as usize) {
                        println!("Stopped at {}", line);
                    }
                }
            }
        },
        Err(err) => {
            println!("{}", err);
        }
    }
}

fn parse_address(addr: &str) -> Option<usize> {
    let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
        &addr[2..]
    } else {
        &addr
    };
    // todo: deal with errors
    usize::from_str_radix(addr_without_0x, 16).ok()
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        // TODO (milestone 3): initialize the DwarfData
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Could not open file {}", target);
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!("Could not debugging symbols from {}: {:?}", target, err);
                std::process::exit(1);
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
            brk_num: 0,
            brk_lists: Vec::new(),
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    if let Some(inferior) = self.inferior.as_mut() {
                        inferior.kill();
                    }
                    if let Some(inferior) = Inferior::new(&self.target, &args, &self.brk_lists) {
                        // Create the inferior
                        self.inferior = Some(inferior);
                        // TODO (milestone 1): make the inferior run
                        // You may use self.inferior.as_mut().unwrap() to get a mutable reference
                        // to the Inferior object
                        let inferior = self.inferior.as_mut().unwrap();
                        cont_inferior(&self.debug_data, inferior);
                    } else {
                        println!("Error starting subprocess");
                    }
                }
                DebuggerCommand::CONTINUE => {
                    if let Some(inferior) = self.inferior.as_mut() {
                        cont_inferior(&self.debug_data, inferior);
                    } else {
                        println!("The program is not being run.")
                    }
                }
                DebuggerCommand::STACKTRACE => {
                    if let Some(inferior) = self.inferior.as_mut() {
                        inferior.print_backtrace(&self.debug_data).unwrap();
                    }
                }
                DebuggerCommand::BREAK(address) => {
                    if address.to_lowercase().starts_with("*") {
                        // todo: deal with errors
                        let address = parse_address(&address[1..]).unwrap();
                        println!("Set breakpoint {} at {:#x}", self.brk_num, address);
                        self.brk_lists.push(address);
                        self.brk_num += 1;

                        if let Some(inferior) = self.inferior.as_mut() {
                            set_brk(inferior, &vec![address]);
                            println!("dddd");
                        }
                    }
                    
                }
                DebuggerCommand::Quit => {
                    if let Some(inferior) = self.inferior.as_mut() {
                        inferior.kill();
                    }
                    return;
                }
            }
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
