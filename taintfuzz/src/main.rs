use std::{
    env, 
    path::PathBuf, 
    fs, 
    process::{Command, Stdio}, 
    fs::OpenOptions, 
    os::fd::AsRawFd, 
    os::unix::{io::RawFd, process::CommandExt}, 
    time::Duration,
    process, 
    ptr::NonNull,
    num::NonZero,
    fs::File,
    borrow::Cow,
    io::Read, 
    io::Write,
    io,
    mem::MaybeUninit,
};

use libafl_qemu::{
    command::NopCommandManager,
    elf::EasyElf,
    modules::{EmulatorModule, EmulatorModuleTuple, StdEdgeCoverageModule, StdEdgeCoverageChildModule, cmplog::CmpLogMap, cmplog::CmpLogChildModule,},
    Emulator, EmulatorModules, GuestAddr, Hook, NopEmulatorDriver, NopSnapshotManager, Qemu,
    SYS_read, SyscallHookResult,
    QemuForkExecutor,
    QemuExitReason,
    QemuExitError,
    TargetSignalHandling,
};

use libafl::{
    inputs::{BytesInput, HasTargetBytes, ResizableMutator, HasMutatorBytes},
    observers::{ConstMapObserver, HitcountsMapObserver, VariableMapObserver, CanTrack, TimeObserver},
    feedbacks::MaxMapFeedback,
    feedbacks::CrashFeedback,
    feedbacks::TimeFeedback,
    state::StdState,
    corpus::InMemoryCorpus,
    corpus::InMemoryOnDiskCorpus,
    corpus::OnDiskCorpus,
    events::SimpleEventManager,
    schedulers::QueueScheduler,
    StdFuzzer,
    Fuzzer,
    HasMetadata,
    state::HasRand,
    state::HasMaxSize,
    executors::{ExitKind, ShadowExecutor, InProcessExecutor},
    mutators::{HavocScheduledMutator, MutationResult, I2SRandReplace, havoc_mutations, StdMOptMutator, tokens_mutations, Mutator, },
    stages::{StdMutationalStage, ShadowTracingStage, CalibrationStage},
    monitors::SimpleMonitor,
    Error,
    state::HasCorpus,
    corpus::{Corpus, CorpusId, Testcase},
    state::{HasExecutions, HasSolutions, HasCurrentTestcase},
    feedback_or, 
    generators::RandPrintablesGenerator,
};

use libafl_bolts::{
    current_nanos, 
    nonzero, 
    Named,
    shmem::{unix_shmem, ShMem, ShMemId, ShMemProvider, StdShMemProvider},
    AsSliceMut,
    rands::StdRand, 
    tuples::tuple_list,
    tuples::Merge, 
    AsSlice,
    ownedref::OwnedMutSlice,
};

use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_ALLOCATED_SIZE, MAX_EDGES_FOUND, EDGES_MAP_DEFAULT_SIZE, CMPLOG_MAP_PTR, CmpLogObserver};

use libc;
use log::{error};
use bcmp::{AlgoSpec, MatchIterator};
use rand::{distributions::Uniform, Rng};

use rlimit::{setrlimit, Resource};

use clap::{Arg, Command as argCommand};

static TMP_DIR: &str = "tmp";
static INPUT_FILE: &str = "cur_input";
static FORKSRV_SOCKET_FILE: &str = "forksrv_socket";
static TRACK_FILE: &str = "track";
static PIN_ROOT_VAR: &str = "PIN_ROOT";
const MAX_INPUT_SIZE: usize = 1048576;



fn read_struct<T, R: Read>(mut read: R) -> io::Result<T> {
    let mut obj = MaybeUninit::<T>::uninit();
    let num_bytes = std::mem::size_of::<T>();
    let buffer = unsafe { std::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, num_bytes) };
    read.read_exact(buffer)?;
    Ok(unsafe { obj.assume_init() })
}

fn read_vector<T, R: Read>(mut read: R, size: usize) -> io::Result<Vec<T>> {
    let mut vec = Vec::<T>::with_capacity(size);
    if size > 0 {
        let num_bytes = std::mem::size_of::<T>() * size;
        unsafe { vec.set_len(size) };
        let buffer = unsafe {
            std::slice::from_raw_parts_mut((&mut vec[..]).as_mut_ptr() as *mut u8, num_bytes)
        };
        read.read_exact(buffer)?;
    }
    Ok(vec)
}

pub trait SetLimit {
    fn mem_limit(&mut self, size: u64) -> &mut Self;
    fn setsid(&mut self) -> &mut Self;
    fn pipe_stdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self;
    //fn dup2(&mut self, src: libc::c_int, dst: libc::c_int) -> &mut Self;
    //fn close_fd(&mut self, fd: libc::c_int) -> &mut Self;
}
impl SetLimit for Command {
    fn mem_limit(&mut self, size: u64) -> &mut Self {
        if size == 0 {
            return self;
        }

        let func = move || {
            let size = size << 20;
            let mem_limit: libc::rlim_t = size;
            let r = libc::rlimit {
                rlim_cur: mem_limit,
                rlim_max: mem_limit,
            };

            let r0 = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            unsafe {
                libc::setrlimit(libc::RLIMIT_AS, &r);
                // libc::setrlimit(libc::RLIMIT_DATA, &r);
                libc::setrlimit(libc::RLIMIT_CORE, &r0);
            };

            Ok(())
        };

        unsafe { self.pre_exec(func) }
    }

    fn setsid(&mut self) -> &mut Self {
        let func = move || {
            unsafe {
                libc::setsid();
            };
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn pipe_stdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self {
        if is_stdin {
            let func = move || {
                let ret = unsafe { libc::dup2(fd, libc::STDIN_FILENO) };
                if ret < 0 {
                    panic!("dup2() failded");
                }
                unsafe {
                    libc::close(fd);
                }
                Ok(())
            };
            unsafe { self.pre_exec(func) }
        } else {
            self
        }
    }
}

pub fn filter_args() -> Vec<String> {
    let mut args = vec![env::args().next().unwrap()];
    let mut args_iter = env::args();
    let mut i = 0;
    let mut parg = vec![];
    while let Some(arg) = args_iter.next() {
        if arg.starts_with("--") {
            args.push(arg);
            args.push(args_iter.next().unwrap());
        } else if arg.starts_with("-") {
            args.push(arg);
            args.push(args_iter.next().unwrap());
        }
        else{
            if i > 0 {
                while let Some(arg) = args_iter.next(){
                    parg.push(arg);
                }
                args.extend(parg.clone());
            }
        }
        i = i + 2;
    }
    args
}

// hook input stdin
#[derive(Default, Clone, Debug)]
struct QemuInputHelper {
    /// initially, the buffer generated by calling BytesInput.target_bytes(). on successive calls
    /// to `SYS_read`, the vector will shrink as bytes are passed from this buffer to the buffer
    /// specified in the syscall
    bytes: Vec<u8>,
}

impl QemuInputHelper {
    /// given an address to use as the address for an mmap'd file, create a new
    /// QemuFilesystemBytesHelper  
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[expect(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)] // no longer a problem with nightly
fn syscall_hook<ET, I, S>(
    // Our instantiated [`EmulatorModules`]
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    // Syscall number
    syscall: i32,
    // Registers
    x0: GuestAddr,
    x1: GuestAddr,
    x2: GuestAddr,
    _x3: GuestAddr,
    _x4: GuestAddr,
    _x5: GuestAddr,
    _x6: GuestAddr,
    _x7: GuestAddr,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let syscall = syscall as i64;

    if syscall == SYS_read && x0 == 0 {
        let input: &mut QemuInputHelper = emulator_modules
            .modules_mut()
            .match_first_type_mut::<QemuInputHelper>()
            .unwrap();
        let clen = input.bytes.len();
        let offset: usize = if x2 == 0 {
            0
        } else if x2 as usize <= clen {
            x2.try_into().unwrap()
        } else {
            clen
        };
        let drained = input.bytes.drain(..offset).as_slice().to_owned();
        let _ = qemu.write_mem(x1, &drained);
        SyscallHookResult::Skip(drained.len() as u64)
    } 
    else {
        SyscallHookResult::Run
    }
}

impl<I, S> EmulatorModule<I, S> for QemuInputHelper
where
    I: HasTargetBytes + Unpin,
    S: Unpin,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, I, S>)
    //hook input syscall
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.pre_syscalls(Hook::Function(syscall_hook::<ET, I, S>));
    }

    fn pre_exec<ET>(
        //process input
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        self.bytes.clear();
        self.bytes
            .extend_from_slice(input.target_bytes().as_slice());
    }
}

// custom mutation
#[derive(Debug, Default)]
pub struct Taintfuzz_mutate {
    file: PathBuf,
    track_bin: String,
    track_args: Vec::<String>,
    cur_input: String,
    uaf_list: Vec::<u64>,
}

pub fn get_pin_log(file: PathBuf) -> io::Result<Vec<u8>>{
    let mut f = match File::open(file.clone()) {
        Ok(file) => file,
        Err(err) => {
            panic!("could not open {:?}: {:?}", file, err);
        },
    };

    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    drop(f);
    //let mut buffer = &buffer[..];
    
    return Ok(buffer);
}


impl<I, S> Mutator<I, S> for Taintfuzz_mutate
where
    S: HasMetadata + HasRand + HasMaxSize + HasExecutions + HasCorpus<I> + HasSolutions<I> + HasCurrentTestcase<I>,
    I: ResizableMutator<u8> + HasMutatorBytes + Clone,
{
    #[expect(clippy::too_many_lines)]
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let size = input.mutator_bytes().len();
        let Some(size) = NonZero::new(size) else {
            return Ok(MutationResult::Skipped);
        };

        //run pin

        if self.track_args.contains(&"@@".to_string()) { // for stdin input
            for tmp in self.track_args.iter_mut(){
                if tmp.contains(&"@@".to_string()){
                    *tmp = self.cur_input.clone();
                }
            }
        }

        let mut child = Command::new(&(self.track_bin.to_string()))
        .args(&(self.track_args.clone()))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().expect("Failed to spawn child process");

        
        if !self.track_args.contains(&"@@".to_string()) { // for stdin input
            let mut stdin = child.stdin.take().expect("Failed to open stdin");
            stdin.write_all(input.mutator_bytes_mut()).expect("Failed to write to stdin");
        }
        child.kill()?;


        // read taint info
        let mut log = get_pin_log(self.file.clone())?;
        let mut buffer = &log[..];

        // handle uaf
        let num_uaf = read_struct::<u32, _>(&mut buffer)? as usize;
        //println!("{:}", num_uaf);
        if num_uaf == 1 {
            //log input as crash
            let uaf_addr = read_struct::<u64, _>(&mut buffer)?;
            if (self.uaf_list.iter().find(|&&x| x == uaf_addr)).is_some() {
                return Ok(MutationResult::Skipped);
            }
            self.uaf_list.push(uaf_addr);
            let mut new_testcase = Testcase::from(input.clone());
            new_testcase.set_executions(*state.executions());
            new_testcase.add_metadata(ExitKind::Oom);
            new_testcase.set_parent_id_optional(*state.corpus().current());
            state.solutions_mut().add(new_testcase).expect("In run_observers_and_save_state solutions failure.(mutation)");
            if let Ok(mut tc) = state.current_testcase_mut() {
                tc.found_objective();
            }
            return Ok(MutationResult::Skipped);
        }
        
        let num_exec = read_struct::<u32, _>(&mut buffer)? as usize;
        let end_exec = read_struct::<u32, _>(&mut buffer)? as usize;
        let num_bof = read_struct::<u32, _>(&mut buffer)? as usize;

        if num_exec == 0 && num_bof == 0 {
            return Ok(MutationResult::Skipped);
        }

        // random choose mutation
        let max_choice = 2;
        let choice_range = Uniform::new(0, max_choice);
        let mut arg = vec![];
        let mut rng = rand::thread_rng();
        
        let mut result = MutationResult::Skipped;

        match rng.sample(choice_range) {
            0 => {// handle command injection
                for _ in 0..num_exec {
                    let size = read_struct::<u32, _>(&mut buffer)?;
                    arg = read_vector::<u8, _>(&mut buffer, size as usize)?;

                    //random mutate or next
                    let n: u32 = rng.gen_range(0, 2);
                    if n > 0 {
                        continue;
                    }

                    let arg_string = String::from_utf8_lossy(arg.as_slice());
                    let mut match_string = input.clone();
                    let bytes = input.mutator_bytes_mut();
                    let match_bytes = match_string.mutator_bytes_mut();
                    let match_iter = MatchIterator::new(arg_string.as_bytes(), match_bytes, AlgoSpec::HashMatch(2));
                    for m in match_iter {
                        println!("Match: {:?}", String::from_utf8_lossy(&bytes[m.first_pos..m.first_end()]));
                        let len = m.first_end() - m.first_pos;
                        let mut new_bytes = ";ls;";
                        new_bytes = &new_bytes[0..len];
                        bytes[m.first_pos..m.first_end()].copy_from_slice(new_bytes.as_bytes());
                        result = MutationResult::Mutated;
                        return Ok(result);
                    }
                }
            },
            1 => {//handle buffer overflow
                read_vector::<u8, _>(&mut buffer, end_exec as usize)?;
                for _ in 0..num_bof {
                    let size = read_struct::<u32, _>(&mut buffer)?;
                    arg = read_vector::<u8, _>(&mut buffer, size as usize)?;

                    //random mutate or next
                    let n: u32 = rng.gen_range(0, 2);
                    if n > 0 {
                        continue;
                    }

                    let arg_string = String::from_utf8_lossy(arg.as_slice());
                    let mut match_string = input.clone();
                    let bytes = input.mutator_bytes_mut();
                    let match_bytes = match_string.mutator_bytes_mut();
                    let match_iter = MatchIterator::new(arg_string.as_bytes(), match_bytes, AlgoSpec::HashMatch(2));
                    for m in match_iter {
                        println!("Match: {:?}", String::from_utf8_lossy(&bytes[m.first_pos..m.first_end()]));
                        let len = m.first_end() - m.first_pos;
                        let nlen: usize = rng.gen_range(len, 2*len);
                        let mut new_bytes = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac";
                        if nlen < 256{
                            new_bytes = &new_bytes[0..nlen];
                            bytes[nlen..].copy_from_slice(&match_bytes[m.first_end()..]);
                            bytes[m.first_pos..m.first_pos+nlen].copy_from_slice(new_bytes.as_bytes());
                        }
                        else{
                            bytes[nlen..].copy_from_slice(&match_bytes[m.first_end()..]);
                            let mut i = 0;
                            while 256*(i+1) < nlen {
                                bytes[m.first_pos+(256*i)..m.first_pos+(256*(i+1))].copy_from_slice(new_bytes.as_bytes());
                                i = i + 1;
                            }
                            new_bytes = &new_bytes[0..(nlen-(256*i))];
                            bytes[m.first_pos+(256*i)..nlen].copy_from_slice(new_bytes.as_bytes());
                        }
                        result = MutationResult::Mutated;
                        return Ok(result);
                    }
                }
            },
            _ => {
                result = MutationResult::Skipped;
            },
        }
        Ok(result)
    }
    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for Taintfuzz_mutate {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("Taintfuzz_mutate");
        &NAME
    }
}

impl Taintfuzz_mutate {
    /// Creates a new `Taintfuzz_mutate` struct.
    #[must_use]
    pub fn new(file: PathBuf, track_bin: String, track_args: Vec::<String>, cur_input: String) -> Self {
        Self{
            file,
            track_bin,
            track_args,
            cur_input,
            uaf_list: vec![],
        }
    }
}


pub fn main(){
    // get args
    let res = match argCommand::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("Taintfuzzer")
        .about("LibAFL-based fuzzer with libdft64")
        .arg(
            Arg::new("in")
                .help("The directory to read initial inputs from ('seeds')")
                .long("libafl-in")
                .short('i')
                .required(true),
        )
        .arg(
            Arg::new("out")
                .help("The directory to place finds in ('corpus')")
                .short('o')
                .long("libafl-out")
                .required(true),
        )
        .arg(
            Arg::new("taint")
                .long("libdft-taint")
                .short('t')
                .help("A file to read tokens from, to be used during fuzzing")
                .required(true),
        )
        .arg(Arg::new("pargs")
            .help("Targeted program (USE_FAST) and arguments. Any \"@@\" will be substituted with the input filename from Angora.")
            .allow_hyphen_values(true)
            .last(true)
            .index(1)
        )
        .try_get_matches_from(filter_args())
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {} -i <input> -o <output> -t <track> -- <program>\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    // set params
    let out_dir = PathBuf::from(res.get_one::<String>("out").unwrap().to_string());
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }

    let in_dir = PathBuf::from(res.get_one::<String>("in").unwrap().to_string());
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let taint = PathBuf::from(res.get_one::<String>("taint").unwrap().to_string());
    if !taint.is_file() {
        println!("Taint at {:?} is not a valid file!", &in_dir);
        return;
    }

    // set pargs
    let mut args_iter = env::args();
    let mut pargs = vec![];
    let mut flag = 0;
    while let Some(arg) = args_iter.next() {
        if flag == 1 {
            pargs.push(arg.clone());
        }
        if arg == "--" {
            flag = 1;
        }
    }

    // set max resources

    const DEFAULT_SOFT_LIMIT: u64 = 1 * 1024 * 1024;
    const DEFAULT_HARD_LIMIT: u64 = 2 * 1024 * 1024;
    assert!(Resource::FSIZE.set(DEFAULT_SOFT_LIMIT, DEFAULT_HARD_LIMIT).is_ok());

    let soft = 16384;
    let hard = soft * 2;
    assert!(setrlimit(Resource::NOFILE, soft, hard).is_ok());

    // fuzz
    let _ = fuzz(in_dir, out_dir, taint, pargs);
}


fn fuzz(
    mut in_dir: PathBuf,
    mut out_dir: PathBuf,
    taint: PathBuf,
    mut pargs: Vec<String>,
) -> Result<(), Error> {
    //set fuzz program and parameters
    let mut track_args = Vec::<String>::new();
    let main_bin = pargs[0].clone();
    let mut main_args: Vec<String> = pargs.drain(1..).collect();
    
    //set pin tool
    let pin_root = env::var(PIN_ROOT_VAR).expect("You should set the environment of PIN_ROOT!");
    let pin_bin = format!("{}/{}", pin_root, "pin");
    let track_bin = pin_bin.to_string();
    let pin_tool = taint.to_str().unwrap().to_owned();
    
    //set pin tool parameters
    track_args.push(String::from("-t"));
    track_args.push(pin_tool);
    track_args.push(String::from("--"));
    track_args.push(main_bin.to_string());
    track_args.extend(main_args.clone());

    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    let mut corpus = out_dir.clone();
    corpus.push("queue");

    // input fd
    out_dir.push(TMP_DIR);
    let mut tmp_dir = out_dir;
    fs::create_dir(&(tmp_dir.to_str().unwrap().to_owned())).unwrap();
    tmp_dir.push(INPUT_FILE);
    let cur_input = tmp_dir.to_str().unwrap().to_owned();
    let mut cur_file = File::create(&cur_input)?;

    // is stdin or other input
    let has_input_arg = main_args.contains(&"@@".to_string());
    for tmp in main_args.iter_mut(){
        if tmp.contains(&"@@".to_string()){
            *tmp = cur_input.clone();
        }
    }
    let is_stdin = !has_input_arg;


    // Create an observation channel using the signals map
    let mut shmem_provider = StdShMemProvider::new()?;
    let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_DEFAULT_SIZE).unwrap();
    let edges = edges_shmem.as_slice_mut();

    // Create an observation channel using the coverage map
    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
            "edges",
            NonNull::new(edges.as_mut_ptr())
                .expect("map ptr is null.")
                .cast::<[u8; EDGES_MAP_DEFAULT_SIZE]>(),
        ))
        .track_indices()
    };
    // run program with qemu
    let mut args = Vec::<String>::new();
    args.push("taintfuzz".to_string()); // append
    args.push(main_bin); // just pad
    args.extend(main_args.clone());
    let modules = tuple_list!(
        QemuInputHelper::new(),
        StdEdgeCoverageChildModule::builder()
            .const_map_observer(edges_observer.as_mut())
            .build()?,
        CmpLogChildModule::default(),
    );
    let emulator: Emulator<
        _, _, _, _, _, _, _
    > = Emulator::empty()
        .qemu_parameters(args)
        .modules(modules)
        .build()
        .unwrap();
    emulator.set_target_crash_handling(&TargetSignalHandling::RaiseSignal);
    let qemu = emulator.qemu(); // create emulator

    let mut harness = |_emulator: &mut Emulator<
        _, _, _, _, _, _, _
        >,  
        input: &BytesInput| {
        unsafe {
            //println!("{:?}", input.target_bytes());
            let _ = cur_file.set_len(0);
            let _ = cur_file.write_all(input.target_bytes().as_ref());
            let qemu_ret = qemu.run();
            match qemu_ret {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                Ok(QemuExitReason::Crash) => return ExitKind::Crash,
                Ok(QemuExitReason::Timeout) => return ExitKind::Timeout,

                Err(QemuExitError::UnexpectedExit) => return ExitKind::Crash,
                _ => panic!("Unexpected QEMU exit: {qemu_ret:?}"),
            }
        };
        ExitKind::Ok
    };


    
    let map_feedback = MaxMapFeedback::new(&edges_observer);

    let time_observer = TimeObserver::new("time");

    // search stage
    let calibration = CalibrationStage::new(&map_feedback);

    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // monitor
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mut mgr = SimpleEventManager::new(mon);

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryOnDiskCorpus::new(corpus).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from(crashes)).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();


    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    let mut cmp_shmem = shmem_provider.uninit_on_shmem::<CmpLogMap>().unwrap();
    let cmplog = cmp_shmem.as_slice_mut();

    // Beginning of a page should be properly aligned.
    #[expect(clippy::cast_ptr_alignment)]
    let cmplog_map_ptr = cmplog
        .as_mut_ptr()
        .cast::<libafl_qemu::modules::cmplog::CmpLogMap>();


    //create executor
    let executor = QemuForkExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        shmem_provider,
        Duration::from_millis(5000),
    )?;
    
    unsafe {
        CMPLOG_MAP_PTR = cmplog_map_ptr;
    }
    let cmplog_observer = unsafe { CmpLogObserver::with_map_ptr("cmplog", cmplog_map_ptr, true) };

    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    // load initial inputs
    // if state.must_load_initial_inputs() {
    //     state
    //         .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[in_dir.clone()])
    //         .unwrap_or_else(|_| {
    //             println!("Failed to load initial corpus at {:?}", &in_dir);
    //             process::exit(0);
    //         });
    //     println!("We imported {} input(s) from disk.", state.corpus().count());
    // }

    // if is_stdin {
    //     // Generator of printable bytearrays of max size 4
    //     let mut generator = RandPrintablesGenerator::new(nonzero!(4));
    // }
    // else{

    // }

    // state
    //     .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
    //     .expect("Failed to generate the initial corpus");

    let mut files = vec![];
    let path = fs::read_dir(in_dir).unwrap();
    for entry in path {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            files.push(entry.path());
        }
    }
    
    let _ = state.load_initial_inputs_by_filenames(&mut fuzzer, &mut executor, &mut mgr, &files);

    let mut cpath = env::current_dir()?;
    cpath.push("track.out");

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        I2SRandReplace::new(), Taintfuzz_mutate::new(cpath, track_bin, track_args, cur_input)
    )));

    // tracing stage
    let tracing = ShadowTracingStage::new();

    // create stages
    let mut stages = tuple_list!(calibration, tracing, i2s);

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    return Ok(());
    

}