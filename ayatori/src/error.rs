use alloc::vec::Vec;
use core::{
    fmt::{self, Debug, Display},
    panic::Location,
};

#[derive(Debug, Clone)]
struct Frame {
    location: &'static Location<'static>,
}

/// An error with an associated (explicitly built) traceback.
#[derive(Clone)]
pub struct Traced<E> {
    trace: Vec<Frame>,
    error: E,
}

impl<E> Traced<E> {
    #[track_caller]
    fn new(error: E) -> Self {
        let location = Location::caller();
        Self {
            trace: [Frame { location }].into(),
            error,
        }
    }

    #[track_caller]
    pub(crate) fn trace<V>(self) -> Traced<V>
    where
        V: From<E>,
    {
        let location = Location::caller();
        let mut trace = self.trace;
        trace.push(Frame { location });
        let error = V::from(self.error);
        Traced { trace, error }
    }

    #[track_caller]
    fn trace_and_map<V, F>(self, f: F) -> Traced<V>
    where
        F: FnOnce(E) -> V,
    {
        // TODO: add tracing info
        Traced {
            error: f(self.error),
            trace: self.trace,
        }
    }

    /// Applies the given predicate to an error.
    /// If it returns an `Err` variant, adds a trace to the error and returns it.
    /// Otherwise returns the `Ok` variant and discards the trace.
    pub fn narrow_down<T, V, F>(self, f: F) -> Result<T, Traced<V>>
    where
        F: FnOnce(E) -> Result<T, V>,
    {
        match f(self.error) {
            Ok(result) => Ok(result),
            Err(error) => Err(Traced {
                error,
                trace: self.trace,
            }),
        }
    }
}

impl<E> From<E> for Traced<E> {
    #[track_caller]
    fn from(source: E) -> Self {
        Self::new(source)
    }
}

impl<E> Debug for Traced<E>
where
    E: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self.error)
    }
}

impl<E> Display for Traced<E>
where
    E: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "{}", self.error)?;
        for frame in &self.trace {
            writeln!(f, "  {}", frame.location)?;
        }
        Ok(())
    }
}

/// A trait for wrapping the error variant of a [`Result`] into [`Traced`].
pub trait IntoTraced<T, E> {
    /// Converts the error variant of a [`Result`] into [`Traced`].
    fn into_traced(self) -> Result<T, Traced<E>>;
}

impl<T, E> IntoTraced<T, E> for Result<T, E> {
    #[track_caller]
    fn into_traced(self) -> Result<T, Traced<E>> {
        // Note: we don't use `map_err()` so that `#[track_caller]` in `Traced::trace_and_map()`
        // could pick up this method's caller.
        match self {
            Ok(value) => Ok(value),
            Err(error) => Err(Traced::new(error)),
        }
    }
}

/// A trait with extension methods for a [`Result`] with a [`Traced`] error.
pub trait ResultExt<T, E> {
    /// Converts the traced error into a new type `V`.
    fn trace<V>(self) -> Result<T, Traced<V>>
    where
        V: From<E>;

    /// Traces the location of the error, applying the given predicate to it.
    fn trace_and_map<V, F>(self, f: F) -> Result<T, Traced<V>>
    where
        F: FnOnce(E) -> V;
}

impl<T, E> ResultExt<T, E> for Result<T, Traced<E>> {
    #[track_caller]
    fn trace<V>(self) -> Result<T, Traced<V>>
    where
        V: From<E>,
    {
        self.trace_and_map(From::from)
    }

    #[track_caller]
    fn trace_and_map<V, F>(self, f: F) -> Result<T, Traced<V>>
    where
        F: FnOnce(E) -> V,
    {
        // Note: we don't use `map_err()` so that `#[track_caller]` in `Traced::trace_and_map()`
        // could pick up this method's caller.
        match self {
            Ok(value) => Ok(value),
            Err(error) => Err(error.trace_and_map(f)),
        }
    }
}

/// An alias for a [`Result`] with a [`Traced`] error.
pub type TResult<T, E> = Result<T, Traced<E>>;
