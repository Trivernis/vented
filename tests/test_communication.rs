use crypto_box::SecretKey;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use vented::event::Event;
use vented::server::data::Node;
use vented::server::server_events::READY_EVENT;
use vented::server::VentedServer;

#[test]
fn test_server_communication() {
    let ping_count = Arc::new(AtomicUsize::new(0));
    let pong_count = Arc::new(AtomicUsize::new(0));
    let ready_count = Arc::new(AtomicUsize::new(0));
    let mut rng = rand::thread_rng();
    let global_secret_a = SecretKey::generate(&mut rng);
    let global_secret_b = SecretKey::generate(&mut rng);
    let nodes = vec![
        Node {
            id: "A".to_string(),
            address: Some("localhost:22222".to_string()),
            public_key: global_secret_a.public_key(),
        },
        Node {
            id: "B".to_string(),
            address: None,
            public_key: global_secret_b.public_key(),
        },
    ];
    let mut server_a = VentedServer::new("A".to_string(), global_secret_a, nodes.clone(), 4);
    let mut server_b = VentedServer::new("B".to_string(), global_secret_b, nodes, 4);
    let wg = server_a.listen("localhost:22222".to_string());
    wg.wait();

    server_a.on("ping", {
        let ping_count = Arc::clone(&ping_count);
        move |_| {
            ping_count.fetch_add(1, Ordering::Relaxed);

            Some(Event::new("pong".to_string()))
        }
    });
    server_b.on("pong", {
        let pong_count = Arc::clone(&pong_count);
        move |_| {
            pong_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    });
    server_a.on(READY_EVENT, {
        let ready_count = Arc::clone(&ready_count);
        move |_| {
            ready_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    });
    server_b.on(READY_EVENT, {
        let ready_count = Arc::clone(&ready_count);
        move |_| {
            ready_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    });
    for _ in 0..10 {
        let wg = server_b
            .emit("A".to_string(), Event::new("ping".to_string()))
            .unwrap();
        wg.wait();
    }
    let wg = server_a
        .emit("B".to_string(), Event::new("pong".to_string()))
        .unwrap();
    wg.wait();

    // wait one second to make sure the servers were able to process the events
    for _ in 0..100 {
        thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(ready_count.load(Ordering::SeqCst), 2);
    assert_eq!(ping_count.load(Ordering::SeqCst), 10);
    assert_eq!(pong_count.load(Ordering::SeqCst), 11);
}
