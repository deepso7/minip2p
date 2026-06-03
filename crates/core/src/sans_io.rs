use alloc::boxed::Box;

/// Common interface for poll-driven Sans-I/O state machines.
///
/// Implementors accept exactly one input mutation at a time, then expose any
/// resulting outputs through repeated calls to [`SansIoProtocol::poll_output`].
/// Drivers should drain outputs until `None` before waiting on external I/O,
/// timers, or application input again.
///
/// The trait is intentionally tiny and fully `no_std` compatible. Concrete
/// protocols keep their own strongly typed input and output enums.
pub trait SansIoProtocol {
    /// Input accepted by the state machine.
    type Input;
    /// Output produced by the state machine.
    type Output;
    /// Error returned when an input is rejected synchronously.
    type Error;

    /// Feeds one input into the state machine.
    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error>;

    /// Returns the next pending output, if any.
    fn poll_output(&mut self) -> Option<Self::Output>;

    /// Returns true when there are no pending outputs.
    fn is_idle(&self) -> bool;
}

impl<P> SansIoProtocol for &mut P
where
    P: SansIoProtocol + ?Sized,
{
    type Input = P::Input;
    type Output = P::Output;
    type Error = P::Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        (**self).handle_input(input)
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        (**self).poll_output()
    }

    fn is_idle(&self) -> bool {
        (**self).is_idle()
    }
}

impl<P> SansIoProtocol for Box<P>
where
    P: SansIoProtocol + ?Sized,
{
    type Input = P::Input;
    type Output = P::Output;
    type Error = P::Error;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        (**self).handle_input(input)
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        (**self).poll_output()
    }

    fn is_idle(&self) -> bool {
        (**self).is_idle()
    }
}
