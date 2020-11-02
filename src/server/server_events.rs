use crate::event_handler::EventHandler;

pub(crate) fn get_server_event_handler() -> EventHandler {
    let handler = EventHandler::new();

    handler
}
