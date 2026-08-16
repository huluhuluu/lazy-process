#[cfg(windows)]
mod windows_impl;

#[cfg(windows)]
pub use windows_impl::*;

#[cfg(not(windows))]
compile_error!("Lazy Process currently supports Windows only");
