use serde::{Deserialize, Serialize};

use crate::event::Event;

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
struct SimplePayload {
    string: String,
    number: u32,
    float: f32,
}

#[test]
fn it_serializes_events() {
    let payload = SimplePayload {
        string: "test".to_string(),
        number: 7,
        float: 2.1,
    };
    let payload_raw = rmp_serde::to_vec(&payload).unwrap();
    let mut event = Event::with_payload("test".to_string(), &payload);
    let event_bytes = event.as_bytes().unwrap();

    assert_eq!(event_bytes[0..2], [0x00, 0x04]);
    assert_eq!(event_bytes[6..14], payload_raw.len().to_be_bytes());
}

#[test]
fn it_deserializes_events() {
    let payload = SimplePayload {
        string: "test".to_string(),
        number: 7,
        float: 2.1,
    };
    let mut event = Event::with_payload("test".to_string(), &payload);
    let event_bytes = event.as_bytes().unwrap();

    let deserialized_event = Event::from_bytes(&mut event_bytes.as_slice()).unwrap();
    assert_eq!(deserialized_event.name, "test".to_string());
    assert_eq!(
        deserialized_event.get_payload::<SimplePayload>().unwrap(),
        payload
    );
}
