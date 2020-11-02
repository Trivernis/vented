use crate::event::Event;
use crate::result::VentedResult;

pub mod tcp;

pub trait VentedServer {
    fn listen(&mut self, address: &str) -> VentedResult<()>;
    fn register_handler<F: 'static>(&mut self, event_name: &str, handler: F)
    where
        F: Fn(Event) -> Option<Event> + Send + Sync;
}
