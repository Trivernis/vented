use std::collections::HashMap;

use crate::event::Event;

#[cfg(test)]
mod tests;

/// A handler for events
pub struct EventHandler {
    event_handlers: HashMap<String, Vec<Box<dyn Fn(Event) -> Option<Event> + Send + Sync>>>,
}

impl EventHandler {
    /// Creates a new vented event_handler
    pub fn new() -> Self {
        Self {
            event_handlers: HashMap::new(),
        }
    }

    /// Adds a handler for the given event
    pub fn on<F: 'static>(&mut self, event_name: &str, handler: F)
        where
            F: Fn(Event) -> Option<Event> + Send + Sync,
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
    pub fn handle_event(&mut self, event: Event) -> Vec<Event> {
        let mut response_events = Vec::new();

        if let Some(handlers) = self.event_handlers.get(&event.name) {
            for handler in handlers {
                if let Some(e) = handler(event.clone()) {
                    response_events.push(e);
                }
            }
        }

        response_events
    }
}
