use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub mod circuits;
pub mod gadgets;
pub mod utils;

