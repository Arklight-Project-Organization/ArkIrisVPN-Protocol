//! Anti-replay sliding window for tunnel data packets.

use crate::constants::ANTI_REPLAY_WINDOW_BITS;

pub struct AntiReplay {
    last_seq: u64,
    window: Vec<u64>,
}

impl AntiReplay {
    pub fn new() -> Self {
        Self {
            last_seq: 0,
            window: vec![0u64; ANTI_REPLAY_WINDOW_BITS / 64],
        }
    }

    pub fn check(&mut self, seq: u64) -> bool {
        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff >= ANTI_REPLAY_WINDOW_BITS as u64 {
                self.window.fill(0);
                self.window[0] = 1;
            } else {
                let shift_chunks = (diff / 64) as usize;
                let shift_bits = (diff % 64) as u32;
                if shift_chunks > 0 {
                    for i in (shift_chunks..self.window.len()).rev() {
                        self.window[i] = self.window[i - shift_chunks];
                    }
                    for i in 0..shift_chunks {
                        self.window[i] = 0;
                    }
                }
                if shift_bits > 0 {
                    let mut carry = 0;
                    for i in 0..self.window.len() {
                        let val = self.window[i];
                        self.window[i] = (val << shift_bits) | carry;
                        carry = val >> (64 - shift_bits);
                    }
                }
                self.window[0] |= 1;
            }
            self.last_seq = seq;
            true
        } else {
            let diff = self.last_seq - seq;
            if diff == 0 || diff >= ANTI_REPLAY_WINDOW_BITS as u64 {
                return false;
            }
            let index = (diff / 64) as usize;
            let bit = (diff % 64) as u32;
            if index >= self.window.len() {
                return false;
            }
            if (self.window[index] >> bit) & 1 == 1 {
                false
            } else {
                self.window[index] |= 1 << bit;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_are_rejected_but_in_window_packets_are_accepted() {
        let mut replay = AntiReplay::new();
        assert!(replay.check(1));
        assert!(!replay.check(1));
        assert!(replay.check(2));
        assert!(replay.check(1));
        assert!(!replay.check(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_packets_outside_window_are_rejected() {
        let mut replay = AntiReplay::new();
        assert!(replay.check(3000));
        assert!(!replay.check(3000 - ANTI_REPLAY_WINDOW_BITS as u64 - 1));
    }
}
