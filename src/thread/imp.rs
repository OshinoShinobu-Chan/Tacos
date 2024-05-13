//! Implementation of kernel threads

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::cell::{RefCell, RefMut};
use core::fmt::{self, Debug};
use core::sync::atomic::{AtomicIsize, AtomicU32, AtomicUsize, Ordering::SeqCst};

use crate::fs::File;
use crate::mem::{kalloc, kfree, PageTable, PG_SIZE};
use crate::sbi::interrupt;
use crate::thread::{current, Manager};
use crate::userproc::UserProc;

pub const PRI_DEFAULT: u32 = 31;
pub const PRI_MAX: u32 = 63;
pub const PRI_MIN: u32 = 0;
pub const STACK_SIZE: usize = PG_SIZE * 4;
pub const STACK_ALIGN: usize = 16;
pub const STACK_TOP: usize = 0x80500000;
pub const MAGIC: usize = 0xdeadbeef;

pub type Mutex<T> = crate::sync::Mutex<T, crate::sync::Intr>;

/* --------------------------------- Thread --------------------------------- */
/// All data of a kernel thread
#[repr(C)]
pub struct Thread {
    tid: isize,
    name: &'static str,
    stack: usize,
    status: Mutex<Status>,
    context: Mutex<Context>,
    bp: usize,
    sp: AtomicUsize,
    pub priority: AtomicU32,
    pub userproc: Mutex<Option<UserProc>>,
    pub pagetable: Option<Mutex<PageTable>>,
    pub children: Mutex<Vec<ThreadInfo>>,
    mut_part: ThreadMut,
}

pub struct ThreadMut {
    pub inner: RefCell<ThreadMutInner>,
}

unsafe impl Sync for ThreadMut {}

pub struct ThreadMutInner {
    fd_table: Vec<Option<(File, usize)>>,
    recycled_fd: VecDeque<usize>,
}

pub struct ThreadInfo {
    thread: Option<Arc<Thread>>,
    tid: usize,
    /// if the thread is not dead, exit code is ```None```
    exit_code: Option<isize>,
}

impl ThreadInfo {
    pub fn new(thread: Arc<Thread>) -> Self {
        ThreadInfo {
            tid: thread.tid as usize,
            thread: Some(thread),
            exit_code: None,
        }
    }

    pub fn dead(&mut self, exit_code: isize) {
        self.thread = None;
        self.exit_code = Some(exit_code);
    }

    pub fn exit_code(&self) -> Option<isize> {
        self.exit_code
    }

    pub fn tid(&self) -> usize {
        self.tid
    }
}

impl ThreadMut {
    pub fn get_mut_part(&self) -> RefMut<'_, ThreadMutInner> {
        self.inner.borrow_mut()
    }
}

impl Thread {
    pub fn new(
        name: &'static str,
        stack: usize,
        priority: u32,
        entry: usize,
        userproc: Option<UserProc>,
        pagetable: Option<PageTable>,
        bp: usize,
        sp: usize,
    ) -> Self {
        /// The next thread's id
        static TID: AtomicIsize = AtomicIsize::new(0);

        Thread {
            tid: TID.fetch_add(1, SeqCst),
            name,
            stack,
            status: Mutex::new(Status::Ready),
            context: Mutex::new(Context::new(stack, entry)),
            priority: AtomicU32::new(priority),
            userproc: Mutex::new(userproc),
            pagetable: pagetable.map(Mutex::new),
            children: Mutex::new(Vec::new()),
            bp,
            sp: AtomicUsize::new(sp),
            mut_part: ThreadMut {
                inner: RefCell::new(ThreadMutInner {
                    // children: Vec::new(),
                    fd_table: Vec::new(),
                    recycled_fd: VecDeque::new(),
                }),
            },
        }
    }

    pub fn id(&self) -> isize {
        self.tid
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn status(&self) -> Status {
        *self.status.lock()
    }

    pub fn set_status(&self, status: Status) {
        *self.status.lock() = status;
    }

    pub fn context(&self) -> *mut Context {
        (&*self.context.lock()) as *const _ as *mut _
    }

    pub fn get_bp(&self) -> usize {
        self.bp
    }

    pub fn get_sp(&self) -> usize {
        self.sp.load(SeqCst)
    }

    pub fn set_sp(&self, sp: usize) {
        self.sp.store(sp, SeqCst)
    }

    pub fn get_mut_part(&self) -> RefMut<'_, ThreadMutInner> {
        self.mut_part.get_mut_part()
    }

    pub fn add_children(&self, thread: Arc<Thread>) {
        self.children.lock().push(ThreadInfo::new(thread));
    }

    /// return true if the child is dead, false is the child is alive, None if the child
    /// doesn't exist
    pub fn check_child(&self, pid: usize) -> Option<bool> {
        self.children
            .lock()
            .iter()
            .find(|child| child.tid == pid)
            .map(|child| child.exit_code.is_some())
    }

    pub fn remove_child(&self, pid: usize) -> isize {
        let mut children = self.children.lock();
        let index = children
            .iter()
            .enumerate()
            .find(|child| child.1.tid == pid)
            .unwrap()
            .0;
        children.swap_remove(index).exit_code.unwrap()
    }

    pub fn dead_child(&self, pid: usize, exit_code: isize) {
        let mut children = self.children.lock();
        let child = children
            .iter()
            .enumerate()
            .find(|child| child.1.tid == pid)
            .map(|child| child.0);
        children[child.unwrap()].dead(exit_code);
    }

    pub fn add_file(&self, file: File, flag: usize) -> usize {
        self.get_mut_part().add_file(file, flag)
    }

    pub fn remove_file(&self, fd: usize) {
        self.get_mut_part().remove_file(fd)
    }

    pub fn get_file(&self, fd: usize) -> Option<(File, usize)> {
        self.get_mut_part().get_file(fd)
    }

    pub fn replace_file(&self, fd: usize, file: File) {
        self.get_mut_part().replace_file(fd, file)
    }

    pub fn overflow(&self) -> bool {
        unsafe { (self.stack as *const usize).read() != MAGIC }
    }
}

impl ThreadMutInner {
    pub fn add_file(&mut self, file: File, flag: usize) -> usize {
        if !self.recycled_fd.is_empty() {
            let index = self.recycled_fd.pop_back().unwrap();
            self.fd_table[index] = Some((file, flag));
            index + 3
        } else {
            self.fd_table.push(Some((file, flag)));
            self.fd_table.len() + 2
        }
    }

    pub fn remove_file(&mut self, fd: usize) {
        let index = fd - 3;
        assert!(self.fd_table.len() > index);
        assert!(self.fd_table[index].is_some());
        self.fd_table[index] = None;
        self.recycled_fd.push_front(index);
    }

    pub fn get_file(&self, fd: usize) -> Option<(File, usize)> {
        self.fd_table.get(fd - 3).and_then(|f| f.clone())
    }

    pub fn replace_file(&mut self, fd: usize, file: File) {
        let index = fd - 3;
        assert!(self.fd_table.len() > index);
        assert!(self.fd_table[index].is_some());
        let flag = self.fd_table[index].clone().unwrap().1;
        self.fd_table[index].replace((file, flag));
    }
}

impl Debug for Thread {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_fmt(format_args!(
            "{}({})[{:?}]",
            self.name(),
            self.id(),
            self.status(),
        ))
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        #[cfg(feature = "debug")]
        kprintln!("[THREAD] {:?}'s resources are released", self);

        kfree(self.stack as *mut _, STACK_SIZE, STACK_ALIGN);
        if let Some(pt) = &self.pagetable {
            unsafe { pt.lock().destroy() };
        }
    }
}

/* --------------------------------- BUILDER -------------------------------- */
pub struct Builder {
    priority: u32,
    name: &'static str,
    function: usize,
    userproc: Option<UserProc>,
    pagetable: Option<PageTable>,
    bp: usize,
    sp: usize,
}

impl Builder {
    pub fn new<F>(function: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        // `*mut dyn FnOnce()` is a fat pointer, box it again to ensure FFI-safety.
        let function: *mut Box<dyn FnOnce()> = Box::into_raw(Box::new(Box::new(function)));

        Self {
            priority: PRI_DEFAULT,
            name: "Default",
            function: function as usize,
            userproc: None,
            pagetable: None,
            bp: 0,
            sp: 0,
        }
    }

    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    pub fn pagetable(mut self, pagetable: PageTable) -> Self {
        self.pagetable = Some(pagetable);
        self
    }

    pub fn userproc(mut self, userproc: UserProc) -> Self {
        self.userproc = Some(userproc);
        self
    }

    pub fn stack(mut self, bp: usize, sp: usize) -> Self {
        self.bp = bp;
        self.sp = sp;
        self
    }

    pub fn build(self) -> Arc<Thread> {
        let stack = kalloc(STACK_SIZE, STACK_ALIGN) as usize;

        // Put magic number at the bottom of the stack.
        unsafe { (stack as *mut usize).write(MAGIC) };

        Arc::new(Thread::new(
            self.name,
            stack,
            self.priority,
            self.function,
            self.userproc,
            self.pagetable,
            self.bp,
            self.sp,
        ))
    }

    /// Spawns a kernel thread and registers it to the [`Manager`].
    /// If it will run in the user environment, then two fields
    /// `userproc` and `pagetable` have to be set properly.
    ///
    /// Note that this function CANNOT be called during [`Manager`]'s initialization.
    pub fn spawn(self) -> Arc<Thread> {
        let new_thread = self.build();
        let current = current();
        current.add_children(new_thread.clone());

        #[cfg(feature = "debug")]
        kprintln!("[THREAD] create {:?}", new_thread);

        Manager::get().register(new_thread.clone());

        // Off you go
        new_thread
    }
}

/* --------------------------------- Status --------------------------------- */
/// States of a thread's life cycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Not running but ready to run
    Ready,
    /// Currently running
    Running,
    /// Waiting for an event to trigger
    Blocked,
    /// About to be destroyed
    Dying,
}

/* --------------------------------- Context -------------------------------- */
/// Records a thread's running status when it switches to another thread,
/// and when switching back, restore its status from the context.
#[repr(C)]
#[derive(Debug)]
pub struct Context {
    /// return address
    ra: usize,
    /// kernel stack
    sp: usize,
    /// callee-saved
    s: [usize; 12],
}

impl Context {
    fn new(stack: usize, entry: usize) -> Self {
        Self {
            ra: kernel_thread_entry as usize,
            // calculate the address of stack top
            sp: stack + STACK_SIZE,
            // s0 stores a thread's entry point. For a new thread,
            // s0 will then be used as the first argument of `kernel_thread`.
            s: core::array::from_fn(|i| if i == 0 { entry } else { 0 }),
        }
    }
}

/* --------------------------- Kernel Thread Entry -------------------------- */

extern "C" {
    /// Entrance of kernel threads, providing a consistent entry point for all
    /// kernel threads (except the initial one). A thread gets here from `schedule_tail`
    /// when it's scheduled for the first time. To understand why program reaches this
    /// location, please check on the initial context setting in [`Manager::create`].
    ///
    /// A thread's actual entry is in `s0`, which is moved into `a0` here, and then
    /// it will be invoked in [`kernel_thread`].
    fn kernel_thread_entry() -> !;
}

global_asm! {r#"
    .section .text
        .globl kernel_thread_entry
    kernel_thread_entry:
        mv a0, s0
        j kernel_thread
"#}

/// Executes the `main` function of a kernel thread. Once a thread is finished, mark
/// it as [`Dying`](Status::Dying).
#[no_mangle]
extern "C" fn kernel_thread(main: *mut Box<dyn FnOnce()>) -> ! {
    let main = unsafe { Box::from_raw(main) };

    interrupt::set(true);

    main();

    super::exit()
}
