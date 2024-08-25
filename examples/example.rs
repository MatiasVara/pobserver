use pobserver::Observer;

fn main() {
    // TODO: Get addr from the name of the functions
    let breakpoints = vec![0x55555555b8a0u64, 0x55555555b890u64];

    let mut observer = Observer::new("../debugee/target/debug/debugee");

    // run child process and return
    observer.run();

    // add breakpoints
    for bp in breakpoints {
        observer.add_breakpoint(bp);
    }

    loop {
        let bp = observer.run_until_breakpoint();
        println!("hit 0x{:x}", bp);
    }
}
