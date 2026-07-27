/// Packet arrival rate and bandwidth estimator.
/// Mirrors CPktTimeWindow from window.cpp.
///
/// Two fixed-capacity ring buffers:
/// - 16-slot arrival-time window → packet receive rate (pkt/s)
/// - 64-slot probe-interval window → bandwidth estimate (pkt/s)
pub struct PktTimeWindow {
    arr_times: [u64; 16],     // packet arrival timestamps (µs)
    arr_ptr: usize,
    arr_count: usize,
    probe_times: [u32; 64],   // inter-probe intervals (µs)
    probe_ptr: usize,
    probe_count: usize,
    probe_time: u64,               // time of last probe1 packet
    last_arr_time: u64,
    min_pkt_snd_int: u32,          // minimum inter-arrival interval observed (µs)
}

impl PktTimeWindow {
    pub fn new() -> Self {
        PktTimeWindow {
            arr_times: [0u64; 16],
            arr_ptr: 0,
            arr_count: 0,
            probe_times: [0u32; 64],
            probe_ptr: 0,
            probe_count: 0,
            probe_time: 0,
            last_arr_time: 0,
            min_pkt_snd_int: u32::MAX,
        }
    }

    /// Called on every incoming data packet arrival.
    pub fn on_pkt_arrival(&mut self, now_us: u64) {
        if self.last_arr_time > 0 {
            let interval = now_us.saturating_sub(self.last_arr_time) as u32;
            if interval > 0 && interval < self.min_pkt_snd_int {
                self.min_pkt_snd_int = interval;
            }
        }
        self.arr_times[self.arr_ptr] = now_us;
        self.arr_ptr = (self.arr_ptr + 1) % 16;
        if self.arr_count < 16 {
            self.arr_count += 1;
        }
        self.last_arr_time = now_us;
    }

    /// Called when a probe packet pair's first packet arrives (seq_no % 16 == 0).
    pub fn probe1_arrival(&mut self, now_us: u64) {
        self.probe_time = now_us;
    }

    /// Called when a probe packet pair's second packet arrives (seq_no % 16 == 1).
    pub fn probe2_arrival(&mut self, now_us: u64) {
        if self.probe_time == 0 {
            return;
        }
        let interval = now_us.saturating_sub(self.probe_time) as u32;
        self.probe_times[self.probe_ptr] = interval;
        self.probe_ptr = (self.probe_ptr + 1) % 64;
        if self.probe_count < 64 {
            self.probe_count += 1;
        }
        self.probe_time = 0;
    }

    /// Estimated receive rate in packets per second.
    pub fn pkt_rcv_speed(&self) -> u32 {
        if self.arr_count < 2 {
            return 0;
        }
        let oldest = self.arr_times[(self.arr_ptr + 16 - self.arr_count) % 16];
        let newest = self.arr_times[(self.arr_ptr + 16 - 1) % 16];
        let span_us = newest.saturating_sub(oldest);
        if span_us == 0 {
            return 0;
        }
        ((self.arr_count as u64 - 1) * 1_000_000 / span_us) as u32
    }

    /// Estimated bandwidth in packets per second, from the median probe interval.
    ///
    /// Sorts into a fixed-size stack array rather than collecting into a `Vec`:
    /// this sits on the ACK path, and the window is bounded at 64 entries, so
    /// there is no reason to touch the allocator here.
    pub fn bandwidth(&self) -> u32 {
        let mut scratch = [0u32; 64];
        let mut len = 0;
        for &v in &self.probe_times[..self.probe_count] {
            if v > 0 {
                scratch[len] = v;
                len += 1;
            }
        }
        if len == 0 {
            return 0;
        }
        let scratch = &mut scratch[..len];
        scratch.sort_unstable();
        let median = scratch[len / 2];
        if median == 0 {
            return 0;
        }
        1_000_000 / median
    }

    /// Minimum observed inter-packet sending interval (µs).
    pub fn min_pkt_snd_int(&self) -> u32 {
        if self.min_pkt_snd_int == u32::MAX { 1 } else { self.min_pkt_snd_int }
    }
}

impl Default for PktTimeWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rcv_speed_estimate() {
        let mut w = PktTimeWindow::new();
        // 16 packets arriving 1ms apart → 1000 pkt/s
        for i in 0..16u64 {
            w.on_pkt_arrival(i * 1000);
        }
        let speed = w.pkt_rcv_speed();
        // ~1000 pkt/s expected
        assert!(speed > 900 && speed < 1100, "speed={speed}");
    }

    #[test]
    fn bandwidth_from_probes() {
        let mut w = PktTimeWindow::new();
        // Probe pairs 100µs apart → 10_000 pkt/s bandwidth
        for i in 0..10u64 {
            w.probe1_arrival(i * 1_000_000);
            w.probe2_arrival(i * 1_000_000 + 100);
        }
        let bw = w.bandwidth();
        assert!(bw > 8_000 && bw < 12_000, "bw={bw}");
    }
}
