use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use vented::client::tcp::VentedTcpClient;
use vented::client::VentedClient;
use vented::event::Event;
use vented::server::tcp::VentedTcpServer;
use vented::server::VentedServer;

#[test]
fn test_pong_event() {
    static ADDRESS: &str = "localhost:22222";
    static PING: &str = "ping";
    static PONG: &str = "pong";
    let ping_count = Arc::new(AtomicUsize::new(0));
    let server_ready = Arc::new(AtomicBool::new(false));

    let mut server = VentedTcpServer::new(1);
    {
        let ping_received = Arc::clone(&ping_count);
        server.on(PING, move |_event| {
            ping_received.fetch_add(1, Ordering::Relaxed);

            Some(Event::new(PONG.to_string()))
        });
    }

    thread::spawn({
        let server_ready = Arc::clone(&server_ready);
        move || {
            server_ready.store(true, Ordering::Relaxed);
            server.listen(ADDRESS).unwrap();
        }
    });

    while !server_ready.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(1));
    }
    let mut client = VentedTcpClient::connect(ADDRESS).unwrap();
    client.emit(Event::new(PING.to_string())).unwrap();
    let response = client.emit(Event::new(PING.to_string())).unwrap();

    assert_eq!(ping_count.load(Ordering::Relaxed), 2);
    assert_eq!(response.name, PONG);
}
