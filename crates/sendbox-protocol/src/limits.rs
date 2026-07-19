use crate::ProtocolError;

pub const HARD_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    max_frame_bytes: usize,
}

impl FrameLimits {
    pub fn new(max_frame_bytes: usize) -> Result<Self, ProtocolError> {
        if max_frame_bytes == 0 || max_frame_bytes > HARD_MAX_FRAME_BYTES {
            return Err(ProtocolError::InvalidFrameLimit {
                requested: max_frame_bytes,
                hard_max: HARD_MAX_FRAME_BYTES,
            });
        }
        Ok(Self { max_frame_bytes })
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}
