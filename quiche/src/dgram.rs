// Copyright (C) 2020, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::BufFactory;
use crate::Error;
use crate::Result;

use std::collections::VecDeque;

/// Action for one queued outgoing DATAGRAM during ordered purge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DgramPurgeDecision {
    /// Retain this DATAGRAM and continue visiting the queue.
    Keep,
    /// Remove this DATAGRAM and continue visiting the queue.
    Drop,
    /// Retain this DATAGRAM and the entire unvisited suffix.
    Stop,
}

/// Keeps track of DATAGRAM frames.
#[derive(Default)]
pub struct DatagramQueue<F: BufFactory> {
    queue: VecDeque<F::DgramBuf>,
    queue_max_len: usize,
    queue_bytes_size: usize,
}

impl<F: BufFactory> DatagramQueue<F> {
    pub fn new(queue_max_len: usize) -> Self {
        DatagramQueue {
            queue: VecDeque::new(),
            queue_bytes_size: 0,
            queue_max_len,
        }
    }

    pub fn push(&mut self, data: F::DgramBuf) -> Result<()> {
        if self.is_full() {
            return Err(Error::Done);
        }

        self.queue_bytes_size += data.as_ref().len();
        self.queue.push_back(data);

        Ok(())
    }

    pub fn peek_front_len(&self) -> Option<usize> {
        self.queue.front().map(|d| d.as_ref().len())
    }

    pub fn peek_front_bytes(&self, buf: &mut [u8], len: usize) -> Result<usize> {
        match self.queue.front() {
            Some(d) => {
                let len = std::cmp::min(len, d.as_ref().len());
                if buf.len() < len {
                    return Err(Error::BufferTooShort);
                }

                buf[..len].copy_from_slice(&d.as_ref()[..len]);
                Ok(len)
            },

            None => Err(Error::Done),
        }
    }

    pub fn pop(&mut self) -> Option<F::DgramBuf> {
        if let Some(d) = self.queue.pop_front() {
            self.queue_bytes_size =
                self.queue_bytes_size.saturating_sub(d.as_ref().len());
            return Some(d);
        }

        None
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    pub fn purge<FN: Fn(&[u8]) -> bool>(&mut self, f: FN) {
        // VecDeque::retain can unwind before truncating removed entries.
        // Recount only on unwind; successful filtering still scans just once.
        struct LedgerGuard<'a, T: AsRef<[u8]>> {
            queue: &'a mut VecDeque<T>,
            bytes: &'a mut usize,
            committed: bool,
        }
        impl<T: AsRef<[u8]>> Drop for LedgerGuard<'_, T> {
            fn drop(&mut self) {
                if !self.committed {
                    *self.bytes =
                        self.queue.iter().map(|d| d.as_ref().len()).sum();
                }
            }
        }
        let mut guard = LedgerGuard {
            queue: &mut self.queue,
            bytes: &mut self.queue_bytes_size,
            committed: false,
        };
        let mut bytes = 0;
        guard.queue.retain(|d| {
            let keep = !f(d.as_ref());
            if keep {
                bytes += d.as_ref().len();
            }
            keep
        });
        *guard.bytes = bytes;
        guard.committed = true;
    }

    pub fn purge_ordered<FN: FnMut(&[u8]) -> DgramPurgeDecision>(
        &mut self, mut f: FN,
    ) {
        let mut index = 0;
        while let Some(d) = self.queue.get(index) {
            let len = d.as_ref().len();
            match f(d.as_ref()) {
                DgramPurgeDecision::Keep => index += 1,
                DgramPurgeDecision::Drop => {
                    // At index zero VecDeque::remove is pop_front: an expired
                    // prefix does not visit or move any item in the suffix.
                    let removed = self.queue.remove(index).unwrap();
                    self.queue_bytes_size -= len;
                    drop(removed);
                },
                DgramPurgeDecision::Stop => break,
            }
        }
    }

    pub fn is_full(&self) -> bool {
        self.len() == self.queue_max_len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn byte_size(&self) -> usize {
        self.queue_bytes_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffers::DefaultBufFactory;
    use std::panic::catch_unwind;
    use std::panic::AssertUnwindSafe;

    fn queue(n: usize, wrapped: bool) -> DatagramQueue<DefaultBufFactory> {
        let mut q = DatagramQueue::new(n.max(1));
        if wrapped {
            q.queue.reserve(n);
            for _ in 0..(n / 2).max(1) {
                q.push(vec![0]).unwrap();
                q.pop();
            }
        }
        for i in 0..n {
            q.push(vec![i as u8; i % 7 + 1]).unwrap();
        }
        if wrapped && n >= 7 {
            assert!(!q.queue.as_slices().1.is_empty());
        }
        q
    }

    fn assert_ledger(q: &DatagramQueue<DefaultBufFactory>, ids: &[u8]) {
        assert_eq!(q.queue.iter().map(|d| d[0]).collect::<Vec<_>>(), ids);
        assert_eq!(q.len(), ids.len());
        assert_eq!(q.byte_size(), q.queue.iter().map(Vec::len).sum());
    }

    #[test]
    fn ordered_purge_prefix_visits_only_dropped_items_and_boundary() {
        for wrapped in [false, true] {
            for n in [0, 1, 7, 64] {
                for k in 0..=n {
                    let mut q = queue(n, wrapped);
                    let mut visits = Vec::new();
                    q.purge_ordered(|d| {
                        visits.push(d[0]);
                        if usize::from(d[0]) < k {
                            DgramPurgeDecision::Drop
                        } else {
                            DgramPurgeDecision::Stop
                        }
                    });
                    assert_eq!(
                        visits,
                        (0..n.min(k + 1) as u8).collect::<Vec<_>>()
                    );
                    assert_ledger(&q, &(k as u8..n as u8).collect::<Vec<_>>());
                }
            }
        }
    }

    #[test]
    fn ordered_purge_mixed_matches_full_predicate_until_explicit_stop() {
        for wrapped in [false, true] {
            for mask in 0..256u16 {
                for stop in 0..=8 {
                    let mut q = queue(8, wrapped);
                    let mut expected = queue(8, wrapped);
                    let mut visited = 0;
                    q.purge_ordered(|d| {
                        assert_eq!(usize::from(d[0]), visited);
                        visited += 1;
                        if usize::from(d[0]) == stop {
                            DgramPurgeDecision::Stop
                        } else if mask & (1 << d[0]) != 0 {
                            DgramPurgeDecision::Drop
                        } else {
                            DgramPurgeDecision::Keep
                        }
                    });
                    expected.purge(|d| {
                        usize::from(d[0]) < stop && mask & (1 << d[0]) != 0
                    });
                    assert_eq!(visited, 8.min(stop + 1));
                    assert_eq!(q.queue, expected.queue);
                    assert_eq!(q.byte_size(), expected.byte_size());
                }
            }
        }
    }

    #[test]
    fn purge_panic_preserves_partial_progress_and_byte_ledger() {
        for ordered in [false, true] {
            for wrapped in [false, true] {
                for panic_at in 0..8 {
                    let mut q = queue(8, wrapped);
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        let predicate = |d: &[u8]| {
                            assert_ne!(d[0], panic_at, "classifier panic");
                            d[0] % 2 == 0
                        };
                        if ordered {
                            q.purge_ordered(|d| {
                                if predicate(d) {
                                    DgramPurgeDecision::Drop
                                } else {
                                    DgramPurgeDecision::Keep
                                }
                            });
                        } else {
                            q.purge(predicate);
                        }
                    }));
                    assert!(result.is_err());
                    let ids = (0..8)
                        .filter(|i| *i >= panic_at || i % 2 != 0)
                        .collect::<Vec<_>>();
                    if ordered {
                        assert_ledger(&q, &ids);
                    } else {
                        assert_eq!(
                            q.byte_size(),
                            q.queue.iter().map(Vec::len).sum()
                        );
                    }
                    while q.pop().is_some() {}
                    assert_eq!(q.byte_size(), 0);
                    q.push(vec![42; 11]).unwrap();
                    assert_eq!(q.byte_size(), 11);
                }
            }
        }
    }
}
