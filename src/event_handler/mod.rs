use std::collections::HashMap;

use crate::event::Event;
use async_std::prelude::*;
use async_std::sync::Arc;
use async_std::task;
use parking_lot::Mutex;
use std::pin::Pin;

#[cfg(test)]
mod tests;

pub trait EventCallback:
    Fn(Event) -> Pin<Box<dyn Future<Output = Option<Event>>>> + Send + Sync
{
}

/// A handler for events
#[derive(Clone)]
pub struct EventHandler {
    event_handlers: Arc<
        Mutex<
            HashMap<
                String,
                Vec<
                    Box<
                        dyn Fn(Event) -> Pin<Box<dyn Future<Output = Option<Event>>>> + Send + Sync,
                    >,
                >,
            >,
        >,
    >,
}

impl EventHandler {
    /// Creates a new vented event_handler
    pub fn new() -> Self {
        Self {
            event_handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Adds a handler for the given event
    pub fn on<F: 'static>(&mut self, event_name: &str, handler: F)
    where
        F: Fn(Event) -> Pin<Box<dyn Future<Output = Option<Event>>>> + Send + Sync,
    {
        let mut handlers = self.event_handlers.lock();
        match handlers.get_mut(event_name) {
            Some(handlers) => handlers.push(Box::new(handler)),
            None => {
                handlers.insert(event_name.to_string(), vec![Box::new(handler)]);
            }
        }
    }

    /// Handles a single event
    pub async fn handle_event(&mut self, event: Event) -> Vec<Event> {
        let mut option_futures = Vec::new();

        if let Some(handlers) = self.event_handlers.lock().get(&event.name) {
            for handler in handlers {
                let result = handler(event.clone());
                option_futures.push(result);
            }
        }
        task::block_on(async move {
            futures::future::join_all(option_futures)
                .await
                .into_iter()
                .filter_map(|opt| opt)
                .collect::<Vec<Event>>()
        })
    }
}

unsafe impl Send for EventHandler {}
unsafe impl Sync for EventHandler {}
