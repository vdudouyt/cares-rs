//! Indexed min-heap: fallible admission, allocation-free expiry/cancellation.
use std::task::Waker;
use std::time::Instant;
use crate::mem::{Map, NoMemory, Vec};

struct Entry { when: Instant, id: usize, waker: Waker }
impl Entry { fn key(&self) -> (Instant, usize) { (self.when, self.id) } }

#[derive(Default)]
pub(super) struct Timers { heap: Vec<Entry>, positions: Map<usize, usize> }

impl Timers {
    pub(super) fn deadline(&self) -> Option<Instant> { self.heap.first().map(|e| e.when) }

    /// Return any replaced waker to be dropped outside the reactor's borrow.
    pub(super) fn insert(&mut self, when: Instant, id: usize, waker: &Waker) -> Result<Option<Waker>, NoMemory> {
        if let Some(&i) = self.positions.get(&id) {
            let slot = &mut self.heap[i].waker;
            return Ok(if slot.will_wake(waker) { None } else { Some(std::mem::replace(slot, waker.clone())) });
        }
        self.heap.reserve(1)?;
        let index = self.heap.len();
        self.positions.insert(id, index)?;
        // Both containers have space; publishing this entry cannot allocate.
        let _ = self.heap.push(Entry { when, id, waker: waker.clone() });
        self.up(index);
        Ok(None)
    }

    pub(super) fn remove(&mut self, id: usize) -> Option<Waker> {
        let index = self.positions.remove(&id)?;
        let removed = self.heap.swap_remove(index);
        if index < self.heap.len() {
            if let Some(pos) = self.positions.get_mut(&self.heap[index].id) { *pos = index; }
            let index = self.up(index);
            self.down(index);
        }
        Some(removed.waker)
    }

    pub(super) fn pop_due(&mut self, now: Instant) -> Option<Waker> {
        let entry = self.heap.first()?;
        if entry.when > now { return None; }
        self.remove(entry.id)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        for i in [a, b] {
            if let Some(pos) = self.positions.get_mut(&self.heap[i].id) { *pos = i; }
        }
    }
    fn up(&mut self, mut i: usize) -> usize {
        while i != 0 {
            let parent = (i - 1) / 2;
            if self.heap[parent].key() <= self.heap[i].key() { break; }
            self.swap(parent, i);
            i = parent;
        }
        i
    }
    fn down(&mut self, mut i: usize) {
        while i < self.heap.len() / 2 {
            let mut child = i * 2 + 1;
            if child + 1 < self.heap.len() && self.heap[child + 1].key() < self.heap[child].key() { child += 1; }
            if self.heap[i].key() <= self.heap[child].key() { break; }
            self.swap(i, child);
            i = child;
        }
    }
}
