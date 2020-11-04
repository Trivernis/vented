use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use crypto_box::aead::{Aead, Payload};
use parking_lot::Mutex;
use sha2::digest::generic_array::GenericArray;
use sha2::Digest;
use typenum::U24;

use crate::event::Event;
use crate::result::VentedResult;

/// A cryptographical stream object that handles encryption and decryption of streams
#[derive(Clone)]
pub struct CryptoStream {
    send_stream: Arc<Mutex<TcpStream>>,
    recv_stream: Arc<Mutex<TcpStream>>,
    sent_count: Arc<AtomicUsize>,
    recv_count: Arc<AtomicUsize>,
    secret_box: Arc<Mutex<crypto_box::ChaChaBox>>,
}

impl CryptoStream {
    /// Creates a new crypto stream from a given Tcp Stream and with a given secret
    pub fn new(inner: TcpStream, secret_box: crypto_box::ChaChaBox) -> VentedResult<Self> {
        let send_stream = Arc::new(Mutex::new(inner.try_clone()?));
        let recv_stream = Arc::new(Mutex::new(inner));

        Ok(Self {
            send_stream,
            recv_stream,
            sent_count: Arc::new(AtomicUsize::new(0)),
            recv_count: Arc::new(AtomicUsize::new(0)),
            secret_box: Arc::new(Mutex::new(secret_box)),
        })
    }

    /// Sends a new event encrypted
    /// format:
    /// length: u64
    /// data: length
    pub fn send(&self, mut event: Event) -> VentedResult<()> {
        let number = self.sent_count.fetch_add(1, Ordering::SeqCst);
        let nonce = generate_nonce(number);
        let ciphertext = self.secret_box.lock().encrypt(
            &nonce,
            Payload {
                msg: &event.as_bytes(),
                aad: &[],
            },
        )?;
        let mut stream = self.send_stream.lock();
        let mut length_raw = [0u8; 8];
        BigEndian::write_u64(&mut length_raw, ciphertext.len() as u64);

        stream.write(&length_raw)?;
        stream.write(&ciphertext)?;
        stream.flush()?;

        Ok(())
    }

    /// Reads an event from the stream. Blocks until data is received
    pub fn read(&self) -> VentedResult<Event> {
        let mut stream = self.recv_stream.lock();
        let mut length_raw = [0u8; 64];
        stream.read_exact(&mut length_raw)?;

        let length = BigEndian::read_u64(&length_raw);
        let mut ciphertext = vec![0u8; length as usize];
        stream.read_exact(&mut ciphertext)?;

        let number = self.recv_count.fetch_add(1, Ordering::SeqCst);
        let nonce = generate_nonce(number);
        let plaintext = self.secret_box.lock().decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: &[],
            },
        )?;

        Event::from_bytes(&mut &plaintext[..])
    }
}

/// Generates a nonce by hashing the input number which is the message counter
fn generate_nonce(number: usize) -> GenericArray<u8, U24> {
    let result = sha2::Sha256::digest(&number.to_be_bytes()).to_vec();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&result);

    nonce.into()
}
