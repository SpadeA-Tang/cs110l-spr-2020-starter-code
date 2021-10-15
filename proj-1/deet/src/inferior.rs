use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::process::Child;
use std::os::unix::process::CommandExt;
use std::process::Command;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use std::collections::HashMap;


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

pub struct Inferior {
    child: Child,
    ori_val_at_brk: HashMap<usize, u8>,
}

pub fn set_brk(inferior: &mut Inferior, brk_lists: &Vec<usize>) {
    for addr in brk_lists {
        if let Some(ori_val) = inferior.write_byte(*addr, 0xcc).ok() {
            inferior.ori_val_at_brk.insert(*addr, ori_val);
        }
    }
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>, brk_lists: &Vec<usize>) -> Option<Inferior> {
        // TODO: implement me!
        let mut cmd = Command::new(target);
        cmd.args(args);
        unsafe {
            cmd.pre_exec(child_traceme);
        }
        
        let mut inferior = Inferior{
            child: cmd.spawn().ok()?,
            ori_val_at_brk: HashMap::new(),
        };
        let status = inferior.wait(None).ok()?;

        set_brk(&mut inferior, brk_lists);

        match status {
            Status::Exited(_) => None,
            Status::Signaled(_) => None,
            Status::Stopped(sig, _) => {
                match sig {
                    signal::Signal::SIGTRAP => Some(inferior),
                    _ => None
                }
            }
        }
    }

    pub fn print_backtrace(&self, debug_data: &DwarfData) -> Result<(), nix::Error> {
        let regs = ptrace::getregs(self.pid())?;
        let mut instruction_ptr = regs.rip as usize;
        let mut base_ptr = regs.rbp as usize;
        loop {
            let func_name = debug_data.get_function_from_addr(instruction_ptr).unwrap();
            println!("{} {}", func_name, 
                debug_data.get_line_from_addr(regs.rip as usize).unwrap());
            if func_name == "main" {
                break;
            }
            instruction_ptr = ptrace::read(self.pid(), (base_ptr + 8) as ptrace::AddressType)? as usize;
            base_ptr = ptrace::read(self.pid(), base_ptr as ptrace::AddressType)? as usize;
        }
        
        Ok(())
    }

    pub fn kill(&mut self) {
        let pid = self.pid();
        self.child.kill().expect("Kill a non-existed process");
        waitpid(pid, None).expect("Something wrong");
    }

    pub fn continue_exec(&self) -> Result<Status, nix::Error> {
        match ptrace::cont(self.pid(), None){
            Ok(_) => self.wait(None),
            Err(err) => Err(err),
        }
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

    /*
    举例: 1001 0110 1101 0011 1111....
    假设地址为 0x1
    那么对齐后为0
    从地址0处读取一字为：1001 0110 1101 0011 1111....

    存储一般为小端序，所以读出来实际为：
    ...1111 1101 0011 1001 0110
    所以我们实际想要的byte为1101 0011

    这里通过 (word >> 8 * byte_offset) & 0xff 来获得， 8 * byte_offset 计算出需要右移多少个bit 
    （注意offset对应的是byte，所以乘8），0xff只取一个byte，所以可以获取1101 0011

    然后masked_word 通过 word & !(0xff << 8 * byte_offset)  运算清0我们才获取的那个位置的值，但保留其他bit的值。
    即...1111    **1101 0011**    1001 0110  变为 ...1111 0000 0000 1001 0110

    然后再通过或运算注入我们需要注入的值
    */
    fn write_byte(&mut self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        // equal to addr (addr / 8) * 8
        println!("write_byte called with addr {:#x} and val {}", addr, val);
        let aligned_addr = align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType)? as u64;
        // 
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        ptrace::write(
            self.pid(), 
            aligned_addr as ptrace::AddressType, 
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }
}

use std::mem::size_of;
fn align_addr_to_word(addr: usize) -> usize {
    addr & (-(size_of::<usize>() as isize) as usize)
}