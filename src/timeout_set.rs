use std::cmp::PartialEq;
use crate::timeout_set::TimeoutState::TimeoutPending;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde_derive::Deserialize;
use crate::timeout_set::TimeoutState::TimeoutElapsed;

#[derive(Debug, PartialEq)]
enum TimeoutState {
    TimeoutElapsed,
    TimeoutPending,
}

#[derive(Debug)]
struct Metadata {
    created: Instant,
    timeout: Duration,
}

impl Metadata {
    fn timeout_state(&self) -> TimeoutState {
        if Instant::now() < self.created + self.timeout {
            TimeoutPending
        } else {
            TimeoutElapsed
        }
    }
}

#[derive(Debug)]
pub struct TimeoutSet<T> {
    data: HashMap<T, Metadata>,
}

impl<T> Default for TimeoutSet<T> {
    fn default() -> Self {
        TimeoutSet {
            data: HashMap::new(),
        }
    }
}

impl<T> TimeoutSet<T>
    where
        T: Eq + std::hash::Hash,
{
    pub fn new() -> Self {
        TimeoutSet::default()
    }

    /// Inserts a new element to this collection with a specified timeout.
    /// After the timeout is elapsed the element will eventually be removed.
    pub fn insert(&mut self, item: T, timeout: Duration) {
        self.remove_expired_items();
        self.data.insert(item, Metadata {
            created: Instant::now(),
            timeout,
        });
    }

    /// Clears all items that are expired.
    pub fn remove_expired_items(&mut self) {
        self.data.retain(|item: &T, metadata: &mut Metadata| {
            metadata.timeout_state() == TimeoutPending
        });
    }

    /// Reports if an item is present and its timeout is not elapsed.
    pub fn contains(&self, item: &T) -> bool {
        let metadata = self.data.get(item);
        if let Some(metadata) = metadata {
            match metadata.timeout_state() {
                TimeoutElapsed => { false }
                TimeoutPending => { true }
            }
        } else {
            false
        }
    }

    /// Returns an item if it is contained in this set and removes it.
    pub(crate) fn pop(&mut self, item: &T) -> Option<T> {
        let (item, metadata) = self.data.remove_entry(item)?;
        if metadata.timeout_state() == TimeoutPending {
            Some(item)
        } else {
            None
        }
    }
}


#[cfg(test)]
mod tests {
    use std::time::Duration;
    use crate::timeout_set::TimeoutSet;

    #[test]
    fn test_insert_contains() {
        let foo = "foo";
        let bar = "bar";

        let mut data: TimeoutSet<String> = TimeoutSet::new();
        data.insert(bar.to_string(), Duration::from_micros(0));
        assert!(data.data.contains_key(&bar.to_string()));
        data.insert(foo.to_string(), Duration::from_secs(1000));
        assert!(!data.data.contains_key(&bar.to_string()));


        assert!(data.contains(&foo.to_string()));
        assert!(!data.contains(&bar.to_string()));

        assert!(data.pop(&foo.to_string()).is_some());
        assert!(data.pop(&foo.to_string()).is_none());
    }
}