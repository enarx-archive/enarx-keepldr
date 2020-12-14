use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

use std::path::{Path, PathBuf};

struct TidySocket<T> {
    path: PathBuf,
    socket: T,
}

impl<T> TidySocket<T> {
    fn new<P: AsRef<Path>>(path: P, sock: T) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            socket: sock,
        }
    }
}

impl<T> std::ops::Deref for TidySocket<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<T> std::ops::DerefMut for TidySocket<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl<T> std::ops::Drop for TidySocket<T> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn main() -> io::Result<()> {
    let listen_path = "/tmp/enarx_unix_echo_to_bin";
    let listener = UnixListener::bind(listen_path).map(|l| TidySocket::new(listen_path, l))?;

    let (mut socket, _) = listener.accept()?;

    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer)?;

    let from_path = "/tmp/enarx_unix_echo_from_bin";
    let mut socket = UnixStream::connect(from_path)
        .map(|s| TidySocket::new(from_path, s))
        .unwrap();
    socket.write_all(&buffer)?;
    Ok(())
}
