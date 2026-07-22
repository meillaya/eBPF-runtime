// SPDX-License-Identifier: Apache-2.0 OR MIT
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub struct SendError<T>(pub T);

#[derive(Debug)]
struct Queue<T> {
    capacity: usize,
    messages: Mutex<VecDeque<T>>,
}

#[derive(Debug, Clone)]
pub struct BoundedChannel<T> {
    queue: Arc<Queue<T>>,
}
impl<T> BoundedChannel<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Arc::new(Queue {
                capacity,
                messages: Mutex::new(VecDeque::with_capacity(capacity)),
            }),
        }
    }
    pub fn try_send(&self, msg: T) -> Result<(), SendError<T>> {
        let mut messages = self.queue.messages.lock();
        if messages.len() == self.queue.capacity {
            Err(SendError(msg))
        } else {
            messages.push_back(msg);
            Ok(())
        }
    }
    pub fn try_recv(&self) -> Option<T> {
        self.queue.messages.lock().pop_front()
    }
    pub fn len(&self) -> usize {
        self.queue.messages.lock().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPriority {
    Control,
    Data,
}

#[derive(Debug, Clone)]
pub struct PriorityBoundedChannel<T> {
    control: BoundedChannel<T>,
    data: BoundedChannel<T>,
}
impl<T> PriorityBoundedChannel<T> {
    pub fn new(control_capacity: usize, data_capacity: usize) -> Self {
        Self {
            control: BoundedChannel::new(control_capacity),
            data: BoundedChannel::new(data_capacity),
        }
    }
    pub fn try_send_with_priority(
        &self,
        msg: T,
        priority: EventPriority,
    ) -> Result<(), SendError<T>> {
        match priority {
            EventPriority::Control => self.control.try_send(msg),
            EventPriority::Data => self.data.try_send(msg),
        }
    }
    pub fn try_recv(&self) -> Option<T> {
        self.control.try_recv().or_else(|| self.data.try_recv())
    }
    pub fn len(&self) -> usize {
        self.control.len().saturating_add(self.data.len())
    }
    pub fn control_len(&self) -> usize {
        self.control.len()
    }
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.control.is_empty() && self.data.is_empty()
    }
}
