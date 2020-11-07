use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use crypto_box::aead::{Aead, Payload};
use parking_lot::Mutex;
use sha2::digest::generic_array::GenericArray;
use sha2::Digest;
use typenum::U24;

use crate::event::Event;
use crate::result::VentedResult;

use crypto_box::ChaChaBox;
pub use crypto_box::PublicKey;
pub use crypto_box::SecretKey;

/// A cryptographical stream object that handles encryption and decryption of streams
#[derive(Clone)]
pub struct CryptoStream {
    send_stream: Arc<Mutex<TcpStream>>,
    recv_stream: Arc<Mutex<TcpStream>>,
    send_secret: Arc<Mutex<EncryptionBox<ChaChaBox>>>,
    recv_secret: Arc<Mutex<EncryptionBox<ChaChaBox>>>,
}

impl CryptoStream {
    /// Creates a new crypto stream from a given Tcp Stream and with a given secret
    pub fn new(
        inner: TcpStream,
        public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> VentedResult<Self> {
        inner.set_nonblocking(false)?;
        let send_stream = Arc::new(Mutex::new(inner.try_clone()?));
        let recv_stream = Arc::new(Mutex::new(inner));
        let send_box = EncryptionBox::new(ChaChaBox::new(public_key, secret_key));
        let recv_box = EncryptionBox::new(ChaChaBox::new(public_key, secret_key));

        Ok(Self {
            send_stream,
            recv_stream,
            send_secret: Arc::new(Mutex::new(send_box)),
            recv_secret: Arc::new(Mutex::new(recv_box)),
        })
    }

    /// Sends a new event encrypted
    /// format:
    /// length: u64
    /// data: length
    pub fn send(&self, mut event: Event) -> VentedResult<()> {
        let ciphertext = self.send_secret.lock().encrypt(&event.as_bytes())?;
        let mut stream = self.send_stream.lock();
        let mut length_raw = [0u8; 8];
        BigEndian::write_u64(&mut length_raw, ciphertext.len() as u64);

        log::trace!("Encoded event '{}' to raw message", event.name);

        stream.write(&length_raw)?;
        stream.write(&ciphertext)?;
        stream.flush()?;

        log::trace!("Event sent");

        Ok(())
    }

    /// Reads an event from the stream. Blocks until data is received
    pub fn read(&self) -> VentedResult<Event> {
        let mut stream = self.recv_stream.lock();
        let mut length_raw = [0u8; 8];
        stream.read_exact(&mut length_raw)?;

        let length = BigEndian::read_u64(&length_raw);
        let mut ciphertext = vec![0u8; length as usize];
        stream.read(&mut ciphertext)?;
        log::trace!("Received raw message");

        let plaintext = self.recv_secret.lock().decrypt(&ciphertext)?;

        let event = Event::from_bytes(&mut &plaintext[..])?;
        log::trace!("Decoded message to event '{}'", event.name);

        Ok(event)
    }

    /// Updates the keys in the inner encryption box
    pub fn update_key(&self, secret_key: &SecretKey, public_key: &PublicKey) {
        let send_box = ChaChaBox::new(public_key, secret_key);
        let recv_box = ChaChaBox::new(public_key, secret_key);
        self.send_secret.lock().swap_box(send_box);
        self.recv_secret.lock().swap_box(recv_box);
        log::trace!("Updated secret");
    }
}

pub struct EncryptionBox<T>
where
    T: Aead,
{
    inner: T,
    counter: usize,
}

impl<T> EncryptionBox<T>
where
    T: Aead,
{
    /// Creates a new encryption box with the given inner value
    pub fn new(inner: T) -> Self {
        Self { inner, counter: 0 }
    }

    /// Swaps the crypto box for a new one
    pub fn swap_box(&mut self, new_box: T) {
        self.inner = new_box;
    }
}

impl EncryptionBox<ChaChaBox> {
    /// Encrypts the given data by using the inner ChaCha box and nonce
    pub fn encrypt(&mut self, data: &[u8]) -> VentedResult<Vec<u8>> {
        let nonce = generate_nonce(self.counter);

        let ciphertext = self.inner.encrypt(
            &nonce,
            Payload {
                aad: &[],
                msg: data,
            },
        )?;
        self.counter += 1;

        Ok(ciphertext)
    }

    /// Decrypts the data by using the inner ChaCha box and nonce
    pub fn decrypt(&mut self, data: &[u8]) -> VentedResult<Vec<u8>> {
        let nonce = generate_nonce(self.counter);

        let plaintext = self.inner.decrypt(
            &nonce,
            Payload {
                msg: data,
                aad: &[],
            },
        )?;
        self.counter += 1;

        Ok(plaintext)
    }
}

/// Generates a nonce by hashing the input number which is the message counter
fn generate_nonce(number: usize) -> GenericArray<u8, U24> {
    let result = sha2::Sha256::digest(&number.to_be_bytes()).to_vec();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&result[0..24]);

    nonce.into()
}
