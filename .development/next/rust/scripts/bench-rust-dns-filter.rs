//! Build directly with rustc --edition=2021 -C opt-level=3.
//! Deterministic benchmark for the panel's actual domain index; no I/O.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering::Relaxed};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size() as isize, Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, old: Layout, size: usize) -> *mut u8 {
        let next = System.realloc(ptr, old, size);
        if !next.is_null() {
            LIVE.fetch_add(size as isize - old.size() as isize, Relaxed);
        }
        next
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

#[path = "../rust/panel/src/dnsserver/catalog"]
mod dnsserver {
    mod index;
    use super::{Relaxed, LIVE};
    use std::{
        hint::black_box,
        io::{Cursor, Write},
        time::Instant,
    };

    pub fn measure() {
        let mut source = Vec::new();
        for i in 0..100_000 {
            writeln!(source, "||ad{i}.example.test^").unwrap();
        }
        let baseline = LIVE.load(Relaxed);
        let start = Instant::now();
        let index = index::Index::read(Cursor::new(&source)).unwrap();
        let build_ms = start.elapsed().as_millis();
        let retained = LIVE.load(Relaxed) - baseline;
        let names = (0..10_000)
            .map(|i| {
                format!(
                    "host.{}{}.example.test",
                    if i % 2 == 0 { "ad" } else { "ok" },
                    (i * 7919) % 100_000
                )
            })
            .collect::<Vec<_>>();
        let start = Instant::now();
        let mut hits = 0;
        for _ in 0..100 {
            for name in &names {
                if let Some(index::Verdict::Block(rule)) = index.lookup(black_box(name), 1) {
                    hits += 1;
                    black_box(rule);
                }
            }
        }
        assert_eq!(hits, 500_000);
        println!(
            "rows={} source={} index={} build_ms={} lookups=1000000 hits={} lookup_ms={}",
            index.len(),
            source.len(),
            retained,
            build_ms,
            hits,
            start.elapsed().as_millis()
        );
    }
}
fn main() {
    dnsserver::measure();
}
