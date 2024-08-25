use pobserver::Observer;
use std::collections::HashMap;

fn main() {
    // TODO: Get addr from the name of the functions

    let mut breakpoints = HashMap::new();

    breakpoints.insert(0x55555555b8a0u64, "event1");
    breakpoints.insert(0x55555555b890u64, "event2");

    let mut observer = Observer::new("../debugee/target/debug/debugee");

    // run child process and return
    observer.run();

    // install breakpoints
    for (addr, &_name) in breakpoints.iter() {
        observer.add_breakpoint(*addr)
    }

    loop {
        let bp = observer.run_until_breakpoint();
        match breakpoints.get(&bp) {
            Some(&name) => println!("Event {} happened", name),
            _ => println!("Don't have Daniel's number."),
        }
    }
}
