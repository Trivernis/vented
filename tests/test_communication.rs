use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use vented::event::Event;
use vented::server::data::Node;
use vented::server::VentedServer;

#[test]
fn test_server_communication() {
    let ping_count = Arc::new(AtomicUsize::new(0));
    let pong_count = Arc::new(AtomicUsize::new(0));
    let nodes = vec![
        Node {
            id: "A".to_string(),
            address: Some("localhost:22222".to_string()),
        },
        Node {
            id: "B".to_string(),
            address: None,
        },
    ];
    let mut server_a = VentedServer::new("A".to_string(), nodes.clone(), 2);
    let mut server_b = VentedServer::new("B".to_string(), nodes, 2);
    server_a.listen("localhost:22222".to_string());
    thread::sleep(Duration::from_millis(10));

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
    for _ in 0..10 {
        server_b
            .emit("A".to_string(), Event::new("ping".to_string()))
            .unwrap();
    }
    server_a
        .emit("B".to_string(), Event::new("pong".to_string()))
        .unwrap();

    // wait one second to make sure the servers were able to process the events
    thread::sleep(Duration::from_secs(1));

    assert_eq!(ping_count.load(Ordering::Relaxed), 10);
    assert_eq!(pong_count.load(Ordering::Relaxed), 11);
}
