use std::borrow::BorrowMut;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use parking_lot::Mutex;
use scheduled_thread_pool::ScheduledThreadPool;

use crate::event::Event;
use crate::event_handler::EventHandler;
use crate::result::VentedResult;
use crate::server::server_events::get_server_event_handler;
use crate::server::VentedServer;
use std::io::Write;

pub struct VentedTcpServer {
    event_handler: Arc<Mutex<EventHandler>>,
    pool: ScheduledThreadPool,
}

impl VentedServer for VentedTcpServer {
    /// Starts listening on the given address
    fn listen(&mut self, address: &str) -> VentedResult<()> {
        let listener = TcpListener::bind(address)?;
        for stream in listener.incoming() {
            log::trace!("Connection received.");
            match stream {
                Ok(stream) => self.handle_connection(stream),
                Err(e) => log::error!("Failed to handle connection: {}", e),
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
    /// Creates a new server that runs on the specified number of threads
    pub fn new(num_threads: usize) -> Self {
        let event_handler = get_server_event_handler();
        let pool = ScheduledThreadPool::new(num_threads);

        Self {
            event_handler: Arc::new(Mutex::new(event_handler)),
            pool,
        }
    }

    /// Handles what happens on connection
    fn handle_connection(&mut self, mut stream: TcpStream) {
        let handler = Arc::clone(&self.event_handler);
        self.pool.execute(move || {
            if let Ok(event) = Event::from_bytes(&mut stream) {
                if let Some(mut event) = handler.lock().handle_event(event) {
                    if let Err(e) = stream.write(&event.as_bytes()) {
                        log::error!("Failed to respond to event: {}", e)
                    }
                }
            } else {
                log::warn!("Failed to create an Event from received bytes.")
            }
        });
    }
}
