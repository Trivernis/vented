# Vented

Vented is an event based TCP server with encryption that uses message pack for payload data.

## Encryption

Vented uses key cryptography to encrypt the connection between the client and the serve.
The authenticity of both parties is validated by global public keys that need to be known
to both parties beforehand. The encryption itself uses randomly generated keys and a nonce
that corresponds to the message number. The crate used for encryption is [crypto_box](https://crates.io/crates/crypto_box)
which the [XChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) encryption.
The crate used for the key exchanges is [x25519-dalek](https://crates.io/crates/x25519-dalek).

## Usage

 ```rust
use vented::server::VentedServer;
use vented::server::data::Node;
use vented::crypto::SecretKey;
use rand::thread_rng;
use vented::event::Event;

fn main() {
    let nodes = vec![
        Node {
            id: "B".to_string(),
            address: None,
            public_key: global_secret_b.public_key() // load it from somewhere
        },
    ];
    // in a real world example the secret key needs to be loaded from somewhere because connections
    // with unknown keys are not accepted.
    let global_secret = SecretKey::new(&mut thread_rng());
    let mut server = VentedServer::new("A".to_string(), global_secret, nodes.clone(), 4);
    
    
    server.listen("localhost:20000".to_string());
    server.on("pong", |_event| {
        println!("Pong!");
        
        None    // the return value is the response event Option<Event>
    });
    server.emit("B".to_string(), Event::new("ping".to_string())).unwrap();
}
 ```