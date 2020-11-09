use std::collections::HashMap;
use std::mem;
use std::sync::Arc;
use std::thread;
use std::thread::{JoinHandle, ThreadId};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use crate::event::Event;
use crate::stream::cryptostream::CryptoStream;
use crate::utils::result::{VentedError, VentedResult};
use crate::utils::sync::AsyncValue;
use crate::WaitGroup;

const MAX_ENQUEUED_EVENTS: usize = 50;
pub const CONNECTION_TIMEOUT_SECONDS: u64 = 5;

#[derive(Clone, Debug)]
pub struct ConcurrentStreamManager {
    max_threads: usize,
    threads: Arc<Mutex<HashMap<ThreadId, JoinHandle<()>>>>,
    emitters: Arc<Mutex<HashMap<String, Sender<(Event, AsyncValue<(), VentedError>)>>>>,
    event_receiver: Receiver<(String, Event)>,
    listener_sender: Sender<(String, Event)>,
}

impl ConcurrentStreamManager {
    pub fn new(max_threads: usize) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();

        Self {
            max_threads,
            threads: Arc::new(Mutex::new(HashMap::new())),
            emitters: Arc::new(Mutex::new(HashMap::new())),
            event_receiver: receiver,
            listener_sender: sender,
        }
    }

    /// Returns if the manager has a connection to the given node
    pub fn has_connection(&self, node: &String) -> bool {
        self.emitters.lock().contains_key(node)
    }

    /// Returns the receiver for events
    pub fn receiver(&self) -> Receiver<(String, Event)> {
        self.event_receiver.clone()
    }

    /// Sends an event and returns an async value with the result
    pub fn send(&self, target: &String, event: Event) -> AsyncValue<(), VentedError> {
        let mut value = AsyncValue::new();
        if let Some(emitter) = self.emitters.lock().get(target) {
            if let Err(_) = emitter.send_timeout(
                (event, value.clone()),
                Duration::from_secs(CONNECTION_TIMEOUT_SECONDS),
            ) {
                value.reject(VentedError::UnreachableNode(target.clone()));
            }
        } else {
            value.reject(VentedError::UnknownNode(target.clone()))
        }

        value
    }

    /// Adds a connection to the manager causing it to start two new threads
    /// This call blocks until the two threads are started up
    pub fn add_connection(&self, stream: CryptoStream) -> VentedResult<()> {
        if self.threads.lock().len() > self.max_threads {
            return Err(VentedError::TooManyThreads);
        }
        let sender = self.listener_sender.clone();
        let recv_id = stream.receiver_node().clone();
        let (emitter, receiver) = crossbeam_channel::bounded(MAX_ENQUEUED_EVENTS);
        self.emitters.lock().insert(recv_id.clone(), emitter);
        let wg = WaitGroup::new();

        let sender_thread = thread::Builder::new()
            .name(format!("sender-{}", stream.receiver_node()))
            .spawn({
                let stream = stream.clone();
                let recv_id = recv_id.clone();
                let emitters = Arc::clone(&self.emitters);
                let threads = Arc::clone(&self.threads);
                let wg = WaitGroup::clone(&wg);

                move || {
                    mem::drop(wg);
                    while let Ok((event, mut future)) = receiver.recv() {
                        if let Err(e) = stream.send(event) {
                            log::debug!("Failed to send event to {}: {}", recv_id, e);
                            future.reject(e);
                            break;
                        }
                        future.resolve(());
                    }
                    emitters.lock().remove(&recv_id);
                    threads.lock().remove(&thread::current().id());
                }
            })?;
        self.threads
            .lock()
            .insert(sender_thread.thread().id(), sender_thread);

        let receiver_thread = thread::Builder::new()
            .name(format!("receiver-{}", stream.receiver_node()))
            .spawn({
                let threads = Arc::clone(&self.threads);
                let wg = WaitGroup::clone(&wg);
                move || {
                    mem::drop(wg);
                    while let Ok(mut event) = stream.read() {
                        event.origin = Some(stream.receiver_node().clone());

                        if let Err(e) = sender.send((stream.receiver_node().clone(), event)) {
                            log::trace!("Failed to get event from {}: {}", recv_id, e);
                            break;
                        }
                    }
                    threads.lock().remove(&thread::current().id());
                }
            })?;
        self.threads
            .lock()
            .insert(receiver_thread.thread().id(), receiver_thread);
        wg.wait();

        Ok(())
    }
}
