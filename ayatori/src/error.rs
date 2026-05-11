use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug, Display},
    panic::Location,
};

#[derive(Debug, Clone)]
struct Frame {
    context: String,
    location: &'static Location<'static>,
}

/// An error with an associated (explicitly built) traceback.
#[derive(Clone)]
pub(crate) struct TracedError {
    trace: Vec<Frame>,
    top: Frame,
}

impl TracedError {
    #[track_caller]
    pub fn new(error: impl Into<String>) -> Self {
        let location = Location::caller();
        Self {
            trace: Vec::new(),
            top: Frame {
                context: error.into(),
                location,
            },
        }
    }

    #[track_caller]
    fn with_context(self, context: impl Into<String>) -> Self {
        let location = Location::caller();
        let mut trace = self.trace;
        trace.push(self.top);
        Self {
            trace,
            top: Frame {
                context: context.into(),
                location,
            },
        }
    }
}

impl Debug for TracedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "{} at {}", self.top.context, self.top.location)?;
        for frame in &self.trace {
            writeln!(f, "  {} at {}", frame.context, frame.location)?;
        }
        Ok(())
    }
}

impl Display for TracedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.top.context)
    }
}

pub(crate) trait Traceable {
    fn with_context(self, context: impl Into<String>) -> Self;
}

impl Traceable for TracedError {
    #[track_caller]
    fn with_context(self, context: impl Into<String>) -> Self {
        self.with_context(context)
    }
}

pub(crate) trait TraceableResult {
    fn or_with_context(self, context: impl FnOnce() -> String) -> Self;
}

impl<T, E> TraceableResult for Result<T, E>
where
    E: Traceable,
{
    #[track_caller]
    fn or_with_context(self, context: impl FnOnce() -> String) -> Self {
        // Note: we don't use `map_err()` so that `#[track_caller]` in `Traced::trace_and_map()`
        // could pick up this method's caller.
        match self {
            Ok(value) => Ok(value),
            Err(error) => Err(error.with_context(context())),
        }
    }
}
