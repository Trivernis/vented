use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::event::Event;
use crate::event_handler::EventHandler;
use async_std::task;

#[test]
fn it_handles_events() {
    let mut handler = EventHandler::new();
    let call_count = Arc::new(AtomicUsize::new(0));
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test", move |event| {
            let call_count = Arc::clone(&call_count);
            Box::pin(async move {
                call_count.fetch_add(1, Ordering::Relaxed);

                Some(event)
            })
        });
    }
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test", move |_event| {
            let call_count = Arc::clone(&call_count);
            Box::pin(async move {
                call_count.fetch_add(1, Ordering::Relaxed);

                None
            })
        });
    }
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test2", move |_event| {
            let call_count = Arc::clone(&call_count);
            Box::pin(async move {
                call_count.fetch_add(1, Ordering::Relaxed);

                None
            })
        });
    }
    {
        let call_count = Arc::clone(&call_count);
        handler.on("test2", move |_event| {
            let call_count = Arc::clone(&call_count);
            Box::pin(async move {
                call_count.fetch_add(1, Ordering::Relaxed);

                None
            })
        })
    }

    task::block_on(async move {
        handler.handle_event(Event::new("test".to_string())).await;
        handler.handle_event(Event::new("test".to_string())).await;
        handler.handle_event(Event::new("test2".to_string())).await;
    });

    assert_eq!(call_count.load(Ordering::Relaxed), 6)
}
