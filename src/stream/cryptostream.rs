/*
 * vented asynchronous event based tcp server
 * Copyright (C) 2020 trivernis
 * See LICENSE for more information
 */

use async_std::prelude::*;

use byteorder::{BigEndian, ByteOrder};
use crypto_box::aead::{Aead, Payload};
use crypto_box::{ChaChaBox, SecretKey};
use generic_array::GenericArray;
use parking_lot::Mutex;
use sha2::Digest;
use std::sync::Arc;
use typenum::*;
use x25519_dalek::PublicKey;

use crate::event::Event;
use crate::utils::result::VentedResult;
use async_std::net::{Shutdown, TcpStream};

/// A cryptographical stream object that handles encryption and decryption of streams
#[derive(Clone)]
pub struct CryptoStream {
    recv_node_id: String,
    stream: TcpStream,
    send_secret: Arc<Mutex<EncryptionBox<ChaChaBox>>>,
    recv_secret: Arc<Mutex<EncryptionBox<ChaChaBox>>>,
}

impl CryptoStream {
    /// Creates a new crypto stream from a given Tcp Stream and with a given secret
    pub fn new(
        node_id: String,
        inner: TcpStream,
        public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> VentedResult<Self> {
        let send_box = EncryptionBox::new(ChaChaBox::new(public_key, secret_key));
        let recv_box = EncryptionBox::new(ChaChaBox::new(public_key, secret_key));

        Ok(Self {
            recv_node_id: node_id,
            stream: inner,
            send_secret: Arc::new(Mutex::new(send_box)),
            recv_secret: Arc::new(Mutex::new(recv_box)),
        })
    }

    /// Sends a new event encrypted
    /// format:
    /// length: u64
    /// data: length
    pub async fn send(&mut self, mut event: Event) -> VentedResult<()> {
        let ciphertext = self.send_secret.lock().encrypt(&event.as_bytes())?;
        let mut length_raw = [0u8; 8];
        BigEndian::write_u64(&mut length_raw, ciphertext.len() as u64);

        log::trace!("Encoded event '{}' to raw message", event.name);

        self.stream.write(&length_raw).await?;
        self.stream.write(&ciphertext).await?;
        self.stream.flush().await?;

        log::trace!("Event sent");

        Ok(())
    }

    /// Reads an event from the stream. Blocks until data is received
    pub async fn read(&mut self) -> VentedResult<Event> {
        let mut length_raw = [0u8; 8];
        self.stream.read_exact(&mut length_raw).await?;

        let length = BigEndian::read_u64(&length_raw);
        let mut ciphertext = vec![0u8; length as usize];
        self.stream.read(&mut ciphertext).await?;
        log::trace!("Received raw message");

        let plaintext = self.recv_secret.lock().decrypt(&ciphertext)?;

        let event = Event::from(&mut &plaintext[..])?;
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

    pub fn receiver_node(&self) -> &String {
        &self.recv_node_id
    }

    /// Closes both streams
    pub fn shutdown(&mut self) -> VentedResult<()> {
        self.stream.shutdown(Shutdown::Both)?;

        Ok(())
    }
}

pub struct EncryptionBox<T>
where
    T: Aead,
{
    inner: T,
    counter: u128,
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
fn generate_nonce(number: u128) -> GenericArray<u8, U24> {
    let mut number_raw = [0u8; 16];
    BigEndian::write_u128(&mut number_raw, number);
    let result = sha2::Sha256::digest(&number_raw).to_vec();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&result[0..24]);

    nonce.into()
}
