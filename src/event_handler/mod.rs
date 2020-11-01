use crate::event::Event;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;

#[cfg(test)]
mod tests;

/// A handler for events
pub struct EventHandler<T> {
    event_handlers: HashMap<String, Vec<Box<dyn Fn(&Event<T>)>>>,
}

impl<T> EventHandler<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Creates a new vented event_handler
    pub fn new() -> Self {
        Self {
            event_handlers: HashMap::new(),
        }
    }

    /// Adds a handler for the given event
    pub fn on<F: 'static>(&mut self, event_name: &str, handler: F)
    where
        F: Fn(&Event<T>),
    {
        match self.event_handlers.get_mut(event_name) {
            Some(handlers) => handlers.push(Box::new(handler)),
            None => {
                self.event_handlers
                    .insert(event_name.to_string(), vec![Box::new(handler)]);
            }
        }
    }

    /// Handles a single event
    pub fn handle_event(&mut self, event: Event<T>) -> bool {
        if let Some(handlers) = self.event_handlers.get(&event.name) {
            handlers.iter().for_each(|handler| handler(&event));

            true
        } else {
            false
        }
    }
}
