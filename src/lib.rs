#![allow(non_upper_case_globals)]
#![feature(libc, test)]
extern crate test;
extern crate seccomp;
extern crate libc;
extern crate parking_lot;

use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use seccomp::*;

use parking_lot::{Mutex, Condvar};

pub const NR_read: usize = 0;
pub const NR_write: usize = 1;
pub const NR_open: usize = 2;
pub const NR_close: usize = 3;
pub const NR_stat: usize = 4;
pub const NR_fstat: usize = 5;
pub const NR_poll: usize = 7;
pub const NR_lseek: usize = 8;
pub const NR_mmap: usize = 9;
pub const NR_mprotect: usize = 10;
pub const NR_munmap: usize = 11;
pub const NR_brk: usize = 12;
pub const NR_rt_sigreturn: usize = 15;
pub const NR_ioctl: usize = 16;
pub const NR_access: usize = 21;
pub const NR_madvise: usize = 28;
pub const NR_socket: usize = 41;
pub const NR_connect: usize = 42;
pub const NR_sendto: usize = 44;
pub const NR_recvfrom: usize = 45;
pub const NR_recvmsg: usize = 47;
pub const NR_bind: usize = 49;
pub const NR_getsockname: usize = 51;
pub const NR_clone: usize = 56;
pub const NR_exit: usize = 60;
pub const NR_readlink: usize = 89;
pub const NR_getuid: usize = 102;
pub const NR_sigaltstack: usize = 131;
pub const NR_futex: usize = 202;
pub const NR_sched_getaffinity: usize = 204;
pub const NR_exit_group: usize = 231;
pub const NR_set_robust_list: usize = 273;
pub const NR_sendmmsg: usize = 307;
pub const NR_getrandom: usize = 318;

trait FnBox {
    fn call_box(self: Box<Self>);
}

impl<F: FnOnce()> FnBox for F {
    fn call_box(self: Box<F>) {
        (*self)()
    }
}

type Thunk<'a> = Box<FnBox + Send + 'a>;

pub struct Sandbox {
    t: std::thread::JoinHandle<()>,
    job_sender: Sender<Thunk<'static>>, // job_receiver: Arc<Receiver<Thunk<'static>>>,
    cond: Arc<(Mutex<bool>, Condvar)>,
    should_run: Arc<AtomicBool>,
}

impl Sandbox {
    pub fn new(rules: Vec<Rule>, action: Action) -> Sandbox {
        let (job_tx, rx) = channel::<Thunk<'static>>();

        let builder = thread::Builder::new().name("sandbox".to_owned());

        let should_run = Arc::new(AtomicBool::new(true));
        let should_run2 = should_run.clone();
        let pair = Arc::new((Mutex::new(true), Condvar::new()));
        let pair2 = pair.clone();

        let rules = {
            let mut def_rules = default_rules();
            def_rules.extend(rules.into_iter());
            def_rules
        };

        let t = builder.spawn(move || {
                           let mut ctx = Context::default(action).unwrap();
                           for rule in rules {
                               ctx.add_rule(rule).unwrap();
                           }

                           ctx.load().unwrap();

                           loop {

                               let &(ref lock, ref cvar) = &*pair;
                               {
                                   let mut started = lock.lock();
                                   while !*started {
                                       cvar.wait(&mut started);
                                   }
                                   *started = false;
                               }
                               if !should_run2.load(Ordering::Relaxed) {
                                   break;
                               }

                               let job = rx.recv().unwrap();
                               job.call_box();
                           }
                       })
                       .unwrap();

        Sandbox {
            t: t,
            job_sender: job_tx,
            cond: pair2.clone(),
            should_run: should_run.clone(),
        }
    }

    pub fn run<F, T>(&self, f: F) -> T
        where F: Send + 'static + FnOnce() -> T,
              T: Send + 'static
    {
        let (tx, rx) = channel();

        let &(ref lock, ref cvar) = &*self.cond;
        cvar.notify_all();

        self.job_sender
            .send(Box::new(move || {
                tx.send(f()).unwrap();
            }))
            .unwrap();

        let r = rx.recv().unwrap();
        let mut started = lock.lock();
        *started = true;
        r
    }
    pub fn close(self) {
        self.should_run.store(false, Ordering::Relaxed);
        let &(_, ref cvar) = &*self.cond;
        cvar.notify_all();
        self.t.join().unwrap();
    }
}



fn default_rules() -> Vec<Rule> {
    vec![Rule::new(NR_futex,
                   Compare::arg(0)
                       .with(0)
                       .using(Op::Ge)
                       .build()
                       .unwrap(),
                   Action::Allow),
         Rule::new(NR_sigaltstack,
                   Compare::arg(0)
                       .with(0)
                       .using(Op::Gt)
                       .build()
                       .unwrap(),
                   Action::Allow),
         Rule::new(NR_exit_group,
                   Compare::arg(0)
                       .with(0)
                       .using(Op::Ge)
                       .build()
                       .unwrap(),
                   Action::Allow),
         Rule::new(NR_exit,
                   Compare::arg(0)
                       .with(0)
                       .using(Op::Ge)
                       .build()
                       .unwrap(),
                   Action::Allow),
         Rule::new(13,
                   Compare::arg(0)
                       .with(0)
                       .using(Op::Ge)
                       .build()
                       .unwrap(),
                   Action::Allow),
         Rule::new(NR_munmap,
                   Compare::arg(0)
                       .with(0)
                       .using(Op::Ge)
                       .build()
                       .unwrap(),
                   Action::Allow),
         Rule::new(NR_madvise,
                   Compare::arg(0)
                       .with(0)
                       .using(Op::Ge)
                       .build()
                       .unwrap(),
                   Action::Allow)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccomp::*;
    use test::Bencher;

    fn fib(n: u64) -> u64 {
        let mut a: u64 = 1;
        let mut b: u64 = 1;

        for _ in 0..n - 2 {
            let tmp: u64 = b;
            b = a + b;
            a = tmp;
        }

        return b;

    }

    #[bench]
    fn bench_sandbox(bencher: &mut Bencher) {
        let sandbox_exec: Sandbox = Sandbox::new(vec![Rule::new(NR_write,
                                                                Compare::arg(0)
                                                                    .with(0)
                                                                    .using(Op::Ge)
                                                                    .build()
                                                                    .unwrap(),
                                                                Action::Allow)],
                                                 Action::Trap);

        bencher.iter(|| sandbox_exec.run(move || fib(50_000)));

        sandbox_exec.close();
    }

    #[bench]
    fn bench_no_sandbox(bencher: &mut Bencher) {
        bencher.iter(|| fib(50_000));
    }
}
