/*
 * vented asynchronous event based tcp server
 * Copyright (C) 2020 trivernis
 * See LICENSE for more information
 */

use std::mem;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::WaitGroup;

pub struct AsyncValue<V, E> {
    value: Arc<Mutex<Option<V>>>,
    error: Arc<Mutex<Option<E>>>,
    wg: Option<WaitGroup>,
    err_cb: Arc<Mutex<Option<Box<dyn FnOnce(&E) -> () + Send + Sync>>>>,
    ok_cb: Arc<Mutex<Option<Box<dyn FnOnce(&V) -> () + Send + Sync>>>>,
}

impl<V, E> AsyncValue<V, E>
where
    E: std::fmt::Display,
{
    /// Creates the future with no value
    pub fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
            error: Arc::new(Mutex::new(None)),
            wg: Some(WaitGroup::new()),
            err_cb: Arc::new(Mutex::new(None)),
            ok_cb: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates a new AsyncValue with an already resolved value
    pub fn with_value(value: V) -> Self {
        Self {
            value: Arc::new(Mutex::new(Some(value))),
            error: Arc::new(Mutex::new(None)),
            wg: None,
            err_cb: Arc::new(Mutex::new(None)),
            ok_cb: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_error(error: E) -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
            error: Arc::new(Mutex::new(Some(error))),
            wg: None,
            err_cb: Arc::new(Mutex::new(None)),
            ok_cb: Arc::new(Mutex::new(None)),
        }
    }

    pub fn on_error<F>(&mut self, cb: F) -> &mut Self
    where
        F: FnOnce(&E) -> () + Send + Sync + 'static,
    {
        self.err_cb.lock().replace(Box::new(cb));

        self
    }

    pub fn on_success<F>(&mut self, cb: F) -> &mut Self
    where
        F: FnOnce(&V) -> () + Send + Sync + 'static,
    {
        self.ok_cb.lock().replace(Box::new(cb));

        self
    }

    /// Sets the value of the future consuming the wait group
    pub fn resolve(&mut self, value: V) {
        if let Some(cb) = self.ok_cb.lock().take() {
            cb(&value)
        }
        self.value.lock().replace(value);
        mem::take(&mut self.wg);
    }

    /// Sets an error for the value
    pub fn reject(&mut self, error: E) {
        if let Some(cb) = self.err_cb.lock().take() {
            cb(&error)
        }
        self.error.lock().replace(error);
        mem::take(&mut self.wg);
    }

    pub fn result(&mut self, result: Result<V, E>) {
        match result {
            Ok(v) => self.resolve(v),
            Err(e) => self.reject(e),
        }
    }

    pub fn block_unwrap(&mut self) -> V {
        match self.get_value() {
            Ok(v) => v,
            Err(e) => panic!("Unwrap on Err value: {}", e),
        }
    }

    /// Returns the value of the future after it has been set.
    /// This call blocks
    pub fn get_value(&mut self) -> Result<V, E> {
        if let Some(wg) = mem::take(&mut self.wg) {
            wg.wait();
        }
        if let Some(err) = self.error.lock().take() {
            Err(err)
        } else {
            Ok(self.value.lock().take().unwrap())
        }
    }

    /// Returns the value asynchronously
    pub async fn get_value_async(&mut self) -> Result<V, E> {
        while self.value.lock().is_none() {
            async_std::task::sleep(Duration::from_millis(1)).await;
        }
        if let Some(err) = self.error.lock().take() {
            Err(err)
        } else {
            Ok(self.value.lock().take().unwrap())
        }
    }

    /// Returns the value of the future only blocking for the given timeout
    pub fn get_value_with_timeout(&mut self, timeout: Duration) -> Option<Result<V, E>> {
        async_std::task::block_on(self.get_value_with_timeout_async(timeout))
    }

    /// Returns the value of the future asynchronous with a timeout after the given duration
    pub async fn get_value_with_timeout_async(
        &mut self,
        timeout: Duration,
    ) -> Option<Result<V, E>> {
        let start = Instant::now();

        while self.value.lock().is_none() {
            async_std::task::sleep(Duration::from_millis(1)).await;
            if start.elapsed() > timeout {
                break;
            }
        }
        if let Some(err) = self.error.lock().take() {
            Some(Err(err))
        } else if let Some(value) = self.value.lock().take() {
            Some(Ok(value))
        } else {
            None
        }
    }
}

impl<T, E> Clone for AsyncValue<T, E> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            error: Arc::clone(&self.error),
            wg: self.wg.clone(),
            err_cb: Arc::clone(&self.err_cb),
            ok_cb: Arc::clone(&self.ok_cb),
        }
    }
}

unsafe impl<T, E> Sync for AsyncValue<T, E> {}
unsafe impl<T, E> Send for AsyncValue<T, E> {}
