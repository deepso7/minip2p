use core::fmt;

/// A transport limit that cannot work: a zero where a size is needed, or
/// limits that contradict each other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidLimit {
    /// The offending field.
    pub field: &'static str,
    /// What it must satisfy.
    pub requirement: &'static str,
}

impl fmt::Display for InvalidLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid limit `{}`: {}", self.field, self.requirement)
    }
}

impl core::error::Error for InvalidLimit {}
