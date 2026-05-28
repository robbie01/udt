use std::{cmp::Ordering, iter, ops::{RangeBounds, RangeInclusive}};

use range_set::RangeSet;

#[derive(Debug)]
pub struct RcvLossList {
    first: Option<u32>,
    set: RangeSet<[RangeInclusive<u32>; 1]>
}

impl RcvLossList {
    pub fn new() -> Self {
        Self { first: None, set: RangeSet::new() }
    }

    pub fn insert(&mut self, start: i32, end: i32) {
        if self.first.is_none() {
            assert!(self.set.is_empty());
            self.first = Some(start as u32);
        }

        self.set.insert_range(0..=(end as u32).wrapping_sub(start as u32));
    }

    pub fn remove(&mut self, seqno: i32) {
        if let Some(first) = self.first {
            assert!(!self.set.is_empty());
            self.set.remove((seqno as u32).wrapping_sub(first));
            if let Some(new_first) = self.set.iter().next() {
                if new_first != 0 {
                    self.first = self.first.wrapping_add(new_first);
                    s
                }
            } else {
                self.first = None;
            }
        }
    }

    pub fn remove_range(&mut self, start: i32, end: i32) {
        if let Some(first) = self.first {
            assert!(!self.set.is_empty());
            let start = (start as u32).wrapping_sub(first);
            let end = (end as u32).wrapping_sub(first);
            self.set.remove_range(start..=end);
        }
    }

    pub fn get_loss_length(&self) -> usize {
        self.set.len()
    }

    pub fn get_first_lost_seq(&self) -> i32 {
        let ranges = self.set.as_ref();
        if ranges.len() == 0 {
            return -1;
        }
        if ranges.len() == 1 {
            return *ranges[0].start();
        }
        let last_window = [ranges.last().unwrap().clone(), ranges.first().unwrap().clone()];
        let windows = ranges.windows(2)
            .chain(iter::once(&last_window[..]));
        *windows.max_by_key(|rs| seqlen(*rs[0].end(), *rs[1].start())).unwrap()[1].start()
    }

    pub fn get_loss_array(&self, array: &mut [i32]) -> usize {
        let mut lower = self.set.clone();
        let upper = lower.remove_range(i32::MIN..=self.get_first_lost_seq()-1).unwrap_or_else(RangeSet::new);
        lower.iter().chain(upper.iter()).zip(array).map(|(in_, out)| *out = in_).count()
    }
}