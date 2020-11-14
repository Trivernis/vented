use async_std::task;
use crypto_box::SecretKey;
use log::LevelFilter;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vented::event::Event;
use vented::server::data::{Node, ServerTimeouts};
use vented::server::server_events::NODE_LIST_REQUEST_EVENT;
use vented::server::VentedServer;

fn setup() {
    simple_logger::SimpleLogger::new()
        .with_module_level("async_std", LevelFilter::Warn)
        .with_module_level("async_io", LevelFilter::Warn)
        .with_module_level("polling", LevelFilter::Warn)
        .init()
        .unwrap();
}

#[test]
fn test_server_communication() {
    setup();
    let ping_count = Arc::new(AtomicUsize::new(0));
    let pong_count = Arc::new(AtomicUsize::new(0));
    let c_pinged = Arc::new(AtomicBool::new(false));
    let mut rng = rand::thread_rng();
    let global_secret_a = SecretKey::generate(&mut rng);
    let global_secret_b = SecretKey::generate(&mut rng);
    let global_secret_c = SecretKey::generate(&mut rng);

    let nodes = vec![
        Node {
            id: "A".to_string(),
            addresses: vec!["localhost:22222".to_string()],
            public_key: global_secret_a.public_key(),
            trusted: true,
        },
        Node {
            id: "B".to_string(),
            addresses: vec![],
            public_key: global_secret_b.public_key(),
            trusted: false,
        },
        Node {
            id: "C".to_string(),
            addresses: vec![],
            public_key: global_secret_c.public_key(),
            trusted: false,
        },
    ];
    let mut nodes_a = nodes.clone();
    for i in 0..10 {
        nodes_a.push(Node {
            id: format!("Node-{}", i),
            addresses: vec!["192.168.178.1".to_string()],
            public_key: global_secret_c.public_key(),
            trusted: false,
        })
    }

    task::block_on(async {
        let mut server_a = VentedServer::new(
            "A".to_string(),
            global_secret_a,
            nodes_a,
            ServerTimeouts::default(),
        );
        let mut server_b = VentedServer::new(
            "B".to_string(),
            global_secret_b,
            nodes.clone(),
            ServerTimeouts::default(),
        );
        let mut server_c = VentedServer::new(
            "C".to_string(),
            global_secret_c,
            nodes,
            ServerTimeouts::default(),
        );
        server_a.listen("localhost:22222".to_string());

        server_a.on("ping", {
            let ping_count = Arc::clone(&ping_count);
            move |_| {
                let ping_count = Arc::clone(&ping_count);
                Box::pin(async move {
                    ping_count.fetch_add(1, Ordering::Relaxed);

                    Some(Event::new("pong".to_string()))
                })
            }
        });
        server_b.on("pong", {
            let pong_count = Arc::clone(&pong_count);
            move |_| {
                let pong_count = Arc::clone(&pong_count);
                Box::pin(async move {
                    pong_count.fetch_add(1, Ordering::Relaxed);
                    None
                })
            }
        });
        server_c.on("ping", {
            let c_pinged = Arc::clone(&c_pinged);
            move |_| {
                let c_pinged = Arc::clone(&c_pinged);
                Box::pin(async move {
                    c_pinged.store(true, Ordering::Relaxed);
                    None
                })
            }
        });
        for i in 0..10 {
            assert!(server_a
                .emit(format!("Nodes-{}", i), Event::new("ping"))
                .await
                .is_err());
        }
        server_b
            .emit("A", Event::new(NODE_LIST_REQUEST_EVENT))
            .await
            .unwrap();
        server_c
            .emit("A", Event::new("ping".to_string()))
            .await
            .unwrap();
        server_b
            .emit("C", Event::new("ping".to_string()))
            .await
            .unwrap();
        for _ in 0..9 {
            server_b
                .emit("A", Event::new("ping".to_string()))
                .await
                .unwrap();
        }
        server_a
            .emit("B", Event::new("pong".to_string()))
            .await
            .unwrap();
        task::sleep(Duration::from_secs(2)).await;
    });
    // wait one second to make sure the servers were able to process the events

    assert_eq!(ping_count.load(Ordering::SeqCst), 10);
    assert_eq!(pong_count.load(Ordering::SeqCst), 10);
    assert!(c_pinged.load(Ordering::SeqCst));
}
