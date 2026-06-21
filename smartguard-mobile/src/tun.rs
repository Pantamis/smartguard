//! Async TUN over a raw file descriptor.
//!
//! On Android the TUN device is created by `VpnService` (Kotlin); we receive
//! the established fd from its `ParcelFileDescriptor`. `rustyguard-tun`'s device
//! abstraction *creates* devices via ioctls and is macOS/Linux-only, so it
//! can't be reused — instead we adopt the fd directly and drive it with
//! tokio's [`AsyncFd`] readiness, doing raw non-blocking `read`/`write`.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};

use tokio::io::unix::AsyncFd;

/// A TUN device adopted from a raw fd. Owns the fd (closed on drop).
pub struct AsyncTun {
    inner: AsyncFd<File>,
}

impl AsyncTun {
    /// Adopt a raw TUN fd (e.g. a `VpnService` descriptor). Sets it
    /// non-blocking, which [`AsyncFd`] requires.
    ///
    /// # Safety
    /// `fd` must be an open, owned TUN file descriptor; ownership transfers to
    /// the returned `AsyncTun`, which closes it on drop.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        set_nonblocking(fd)?;
        // SAFETY: caller transfers ownership of a valid open fd.
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            inner: AsyncFd::new(file)?,
        })
    }

    /// Read one IP packet into `buf`. Returns the number of bytes read.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            // `impl Read for &File`, so a shared get_ref() is enough.
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(buf)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet from `buf`. Returns the number of bytes written.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.write(buf)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// Set `O_NONBLOCK` on a raw fd via `fcntl`.
pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a presumed-valid fd; we check the return code.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
