extern crate seccomp_rust;
extern crate seccomp;
extern crate stopwatch;

// use seccomp_rust::Sandbox;
use seccomp_rust::*;
use seccomp::*;
use stopwatch::Stopwatch;

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

fn main() {
    let sandbox_exec: Sandbox = Sandbox::new(vec![], Action::Trap);

    let to_fib = vec![500_000; 10_000];

    let mut sw = Stopwatch::start_new();
    // let results = to_fib.into_iter()
    //                     .map(|f| sandbox_exec.run(move || fib(f)))
    //                     .collect::<Vec<_>>();

    // let result = sandbox_exec.run(move || to_fib.into_iter().map(fib).collect::<Vec<_>>());

    let result = to_fib.into_iter().map(fib).collect::<Vec<_>>();
    sw.stop();
    println!("{:?}", sw.elapsed_ms());
    sandbox_exec.close();

}
