use crate::event::Event;
use crate::result::VentedResult;

pub mod tcp;

pub trait VentedClient: Sized {
    fn connect(address: &str) -> VentedResult<Self>;
    fn emit(&mut self, event: Event) -> VentedResult<Event>;
}
