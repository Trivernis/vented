use std::borrow::BorrowMut;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use parking_lot::Mutex;
use scheduled_thread_pool::ScheduledThreadPool;

use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::result::VentedResult;
use crate::server::VentedServer;

pub struct VentedTcpServer {
    event_handler: Arc<Mutex<EventHandler>>,
    pool: ScheduledThreadPool,
}

impl VentedServer for VentedTcpServer {
    fn listen(&mut self, address: &str) -> VentedResult<()> {
        let listener = TcpListener::bind(address)?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => self.handle_connection(stream),
                Err(_) => {}
            }
        }

        Ok(())
    }

    /// Registers an event on the internal event handler
    fn register_handler<F: 'static>(&mut self, event_name: &str, handler: F)
    where
        F: Fn(Event) -> Option<Event> + Send + Sync,
    {
        self.event_handler
            .lock()
            .borrow_mut()
            .on(event_name, handler);
    }
}

impl VentedTcpServer {
    fn handle_connection(&mut self, mut stream: TcpStream) {
        let handler = Arc::clone(&self.event_handler);
        self.pool.execute(move || {
            if let Ok(event) = Event::from_bytes(&mut stream) {
                handler.lock().handle_event(event);
            }
        });
    }
}
