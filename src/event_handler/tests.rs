use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::event::Event;
use crate::event_handler::EventHandler;

#[test]
fn it_handles_events() {
    let mut handler = EventHandler::new();
    let call_count = Arc::new(AtomicUsize::new(0));
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test", move |event| {
            call_count.fetch_add(1, Ordering::Relaxed);

            Some(event)
        });
    }
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test", move |_event| {
            call_count.fetch_add(1, Ordering::Relaxed);

            None
        });
    }
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test2", move |_event| {
            call_count.fetch_add(1, Ordering::Relaxed);

            None
        });
    }
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test2", move |_event| {
            call_count.fetch_add(1, Ordering::Relaxed);

            None
        })
    }

    handler.handle_event(Event::new("test".to_string()));
    handler.handle_event(Event::new("test".to_string()));
    handler.handle_event(Event::new("test2".to_string()));

    assert_eq!(call_count.load(Ordering::Relaxed), 6)
}
