use alloc::{format, string::String, sync::Arc, vec};

use super::session::SessionData;
use crate::{
    entities::{
        AnyTag, Args, ComputedMappingTag, ComputedScalarTag, DeserializeArgs, DeserializeFunction, LocalSignedTag,
        MappingTag, MaybeAttributableError, Message, MessageId, ReceivedTag, RemoteSignedTag, RuntimeError, ScalarTag,
        SenderAttributableMappingFunction, SenderAttributableWithRevealMappingFunction, SenderError,
        SenderErrorWithReveal, SentTag, SerializeAndSignFunction, SerializeArgs, SignedValue, SpuriousError,
        ThirdPartyAttributableMappingFunction, ThirdPartyError, UnattributableError, UnattributableMappingFunction,
        UnattributableMappingFunctionWithRng, UnattributableOptionalScalarFunction, UnattributableScalarFunction,
        UnattributableScalarFunctionWithRng, Value, VerificationError,
    },
    flat_representation::OnError,
    traits::SessionParameters,
};

#[cfg(doc)]
use crate::protocol_user_api::Session;

#[derive_where::derive_where(Debug)]
pub(crate) struct ScalarUnattributableTask<SP: SessionParameters> {
    store_in: ComputedScalarTag,
    function: UnattributableScalarFunction<SP>,
    args: Args<SP>,
}

impl<SP: SessionParameters> ScalarUnattributableTask<SP> {
    pub fn new(store_in: ComputedScalarTag, function: UnattributableScalarFunction<SP>, args: Args<SP>) -> Self {
        Self {
            store_in,
            function,
            args,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        let store_in = ScalarTag::Computed(self.store_in);
        match self.function.call(&self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedScalar { store_in, result }),
            Err(UnattributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => TaskResult(TaskResultEnum::SpuriousError {
                store_in: AnyTag::Scalar(store_in),
                error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<ScalarUnattributableTask<SP>> for Task<SP> {
    fn from(source: ScalarUnattributableTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::ScalarUnattributable(source)))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ScalarUnattributableOptionalTask<SP: SessionParameters> {
    store_in: ComputedScalarTag,
    function: UnattributableOptionalScalarFunction<SP>,
    args: Args<SP>,
}

impl<SP: SessionParameters> ScalarUnattributableOptionalTask<SP> {
    pub fn new(
        store_in: ComputedScalarTag,
        function: UnattributableOptionalScalarFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self {
            store_in,
            function,
            args,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        let store_in = ScalarTag::Computed(self.store_in);
        match self.function.call(&self.args) {
            Ok(result) => TaskResult(result.map_or_else(
                || TaskResultEnum::NoActionNeeded,
                |value| TaskResultEnum::ComputedScalar {
                    store_in,
                    result: value,
                },
            )),
            Err(error) => TaskResult(TaskResultEnum::RuntimeError(error)),
        }
    }
}

impl<SP: SessionParameters> From<ScalarUnattributableOptionalTask<SP>> for Task<SP> {
    fn from(source: ScalarUnattributableOptionalTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::ScalarUnattributableOptional(
            source,
        )))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ElementUnattributableTask<SP: SessionParameters> {
    store_in: ComputedMappingTag,
    function: UnattributableMappingFunction<SP>,
    index: SP::Verifier,
    args: Args<SP>,
}

impl<SP: SessionParameters> ElementUnattributableTask<SP> {
    pub fn new(
        store_in: ComputedMappingTag,
        function: UnattributableMappingFunction<SP>,
        index: SP::Verifier,
        args: Args<SP>,
    ) -> Self {
        Self {
            store_in,
            function,
            index,
            args,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(UnattributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => TaskResult(TaskResultEnum::SpuriousError {
                store_in: AnyTag::Mapping(store_in),
                error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<ElementUnattributableTask<SP>> for Task<SP> {
    fn from(source: ElementUnattributableTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::ElementUnattributable(source)))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ElementSenderAttributableTask<SP: SessionParameters> {
    store_in: ComputedMappingTag,
    function: SenderAttributableMappingFunction<SP>,
    index: SP::Verifier,
    args: Args<SP>,
    on_error: OnError,
}

impl<SP: SessionParameters> ElementSenderAttributableTask<SP> {
    pub fn new(
        store_in: ComputedMappingTag,
        function: SenderAttributableMappingFunction<SP>,
        index: SP::Verifier,
        args: Args<SP>,
        on_error: OnError,
    ) -> Self {
        Self {
            store_in,
            function,
            index,
            args,
            on_error,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => TaskResult(TaskResultEnum::SenderError {
                store_in,
                guilty_party: self.index,
                error,
                on_error: self.on_error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<ElementSenderAttributableTask<SP>> for Task<SP> {
    fn from(source: ElementSenderAttributableTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::ElementSenderAttributable(
            source,
        )))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ElementSenderAttributableWithRevealTask<SP: SessionParameters> {
    store_in: ComputedMappingTag,
    function: SenderAttributableWithRevealMappingFunction<SP>,
    index: SP::Verifier,
    args: Args<SP>,
    on_error: OnError,
}

impl<SP: SessionParameters> ElementSenderAttributableWithRevealTask<SP> {
    pub fn new(
        store_in: ComputedMappingTag,
        function: SenderAttributableWithRevealMappingFunction<SP>,
        index: SP::Verifier,
        args: Args<SP>,
        on_error: OnError,
    ) -> Self {
        Self {
            store_in,
            function,
            index,
            args,
            on_error,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => TaskResult(TaskResultEnum::SenderErrorWithReveal {
                store_in,
                guilty_party: self.index,
                error,
                on_error: self.on_error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<ElementSenderAttributableWithRevealTask<SP>> for Task<SP> {
    fn from(source: ElementSenderAttributableWithRevealTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(
            DeterministicTaskEnum::ElementSenderAttributableWithReveal(source),
        ))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct ElementThirdPartyAttributableTask<SP: SessionParameters> {
    store_in: ComputedMappingTag,
    function: ThirdPartyAttributableMappingFunction<SP>,
    index: SP::Verifier,
    args: Args<SP>,
}

impl<SP: SessionParameters> ElementThirdPartyAttributableTask<SP> {
    pub fn new(
        store_in: ComputedMappingTag,
        function: ThirdPartyAttributableMappingFunction<SP>,
        index: SP::Verifier,
        args: Args<SP>,
    ) -> Self {
        Self {
            store_in,
            function,
            index,
            args,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => {
                TaskResult(TaskResultEnum::ThirdPartyError { store_in, error })
            }
        }
    }
}

impl<SP: SessionParameters> From<ElementThirdPartyAttributableTask<SP>> for Task<SP> {
    fn from(source: ElementThirdPartyAttributableTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::ElementThirdPartyAttributable(
            source,
        )))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct DeserializeElementTask<SP: SessionParameters> {
    store_in: ReceivedTag,
    function: DeserializeFunction<SP>,
    index: SP::Verifier,
    args: DeserializeArgs<SP>,
    on_error: OnError,
}

impl<SP: SessionParameters> DeserializeElementTask<SP> {
    pub fn new(
        store_in: ReceivedTag,
        function: DeserializeFunction<SP>,
        index: SP::Verifier,
        args: DeserializeArgs<SP>,
        on_error: OnError,
    ) -> Self {
        Self {
            store_in,
            function,
            index,
            args,
            on_error,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        let store_in = MappingTag::Received(self.store_in);
        match self.function.call(&self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => TaskResult(TaskResultEnum::SenderError {
                store_in,
                guilty_party: self.index,
                error,
                on_error: self.on_error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<DeserializeElementTask<SP>> for Task<SP> {
    fn from(source: DeserializeElementTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::DeserializeElement(source)))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct RngScalarUnattributableTask<SP: SessionParameters> {
    store_in: ComputedScalarTag,
    function: UnattributableScalarFunctionWithRng<SP>,
    args: Args<SP>,
}

impl<SP: SessionParameters> RngScalarUnattributableTask<SP> {
    pub fn new(store_in: ComputedScalarTag, function: UnattributableScalarFunctionWithRng<SP>, args: Args<SP>) -> Self {
        Self {
            store_in,
            function,
            args,
        }
    }

    pub fn execute(self, rng: &mut SP::Rng) -> TaskResult<SP> {
        let store_in = ScalarTag::Computed(self.store_in);
        match self.function.call(rng, &self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedScalar { store_in, result }),
            Err(UnattributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => TaskResult(TaskResultEnum::SpuriousError {
                store_in: AnyTag::Scalar(store_in),
                error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<RngScalarUnattributableTask<SP>> for Task<SP> {
    fn from(source: RngScalarUnattributableTask<SP>) -> Self {
        Self::Randomized(RandomizedTask(RandomizedTaskEnum::ScalarUnattributable(source)))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct RngElementUnattributableTask<SP: SessionParameters> {
    store_in: ComputedMappingTag,
    function: UnattributableMappingFunctionWithRng<SP>,
    index: SP::Verifier,
    args: Args<SP>,
}

impl<SP: SessionParameters> RngElementUnattributableTask<SP> {
    pub fn new(
        store_in: ComputedMappingTag,
        function: UnattributableMappingFunctionWithRng<SP>,
        index: SP::Verifier,
        args: Args<SP>,
    ) -> Self {
        Self {
            store_in,
            function,
            index,
            args,
        }
    }

    pub fn execute(self, rng: &mut SP::Rng) -> TaskResult<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(rng, &self.index, &self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(UnattributableError::Runtime(error)) => TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => TaskResult(TaskResultEnum::SpuriousError {
                store_in: AnyTag::Mapping(store_in),
                error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<RngElementUnattributableTask<SP>> for Task<SP> {
    fn from(source: RngElementUnattributableTask<SP>) -> Self {
        Self::Randomized(RandomizedTask(RandomizedTaskEnum::ElementUnattributable(source)))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct SerializeAndSignElementTask<SP: SessionParameters> {
    store_in: LocalSignedTag,
    function: SerializeAndSignFunction<SP>,
    index: SP::Verifier,
    args: SerializeArgs<SP>,
}

impl<SP: SessionParameters> SerializeAndSignElementTask<SP> {
    pub fn new(
        store_in: LocalSignedTag,
        function: SerializeAndSignFunction<SP>,
        index: SP::Verifier,
        args: SerializeArgs<SP>,
    ) -> Self {
        Self {
            store_in,
            function,
            index,
            args,
        }
    }

    pub fn execute(self, rng: &mut SP::Rng) -> TaskResult<SP> {
        let store_in = MappingTag::LocalSigned(self.store_in);
        match self.function.call(rng, &self.index, &self.args) {
            Ok(result) => TaskResult(TaskResultEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(error) => TaskResult(TaskResultEnum::RuntimeError(error)),
        }
    }
}

impl<SP: SessionParameters> From<SerializeAndSignElementTask<SP>> for Task<SP> {
    fn from(source: SerializeAndSignElementTask<SP>) -> Self {
        Self::Randomized(RandomizedTask(RandomizedTaskEnum::SerializeAndSignElement(source)))
    }
}

/// An object used to report the result of attempting to send a message to a remote party.
#[derive_where::derive_where(Debug)]
pub struct SendTaskResult<SP: SessionParameters> {
    store_in: MappingTag,
    destination: SP::Verifier,
}

impl<SP: SessionParameters> SendTaskResult<SP> {
    /// Returns a result indicating that the message was successfully sent.
    pub fn success(self) -> TaskResult<SP> {
        TaskResult(TaskResultEnum::Sent {
            store_in: self.store_in,
            destination: self.destination,
        })
    }

    /// Returns a result indicating that there was an error delivering the message.
    pub fn error(self) -> TaskResult<SP> {
        TaskResult(TaskResultEnum::SendError {
            destination: self.destination,
        })
    }
}

/// A task requiring the user to send a message to a remote party.
#[derive_where::derive_where(Debug)]
pub struct SendTask<SP: SessionParameters> {
    store_in: SentTag,
    destination: SP::Verifier,
    signed_value: SignedValue<SP>,
}

impl<SP: SessionParameters> SendTask<SP> {
    pub(crate) fn new(store_in: SentTag, destination: SP::Verifier, signed_value: SignedValue<SP>) -> Self {
        Self {
            store_in,
            destination,
            signed_value,
        }
    }

    /// Returns the message to be sent and an object used to report the result of that.
    pub fn execute(self) -> (Message<SP>, SendTaskResult<SP>) {
        let signed_values = vec![self.signed_value];
        let message = Message::new(self.destination.clone(), signed_values);
        let result = SendTaskResult {
            store_in: MappingTag::Sent(self.store_in),
            destination: self.destination,
        };
        (message, result)
    }
}

impl<SP: SessionParameters> From<SendTask<SP>> for Task<SP> {
    fn from(source: SendTask<SP>) -> Self {
        Self::Send(source)
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct PreprocessMessageTask<SP: SessionParameters> {
    session_data: Arc<SessionData<SP>>,
    message_id: MessageId<SP>,
    signed_value: SignedValue<SP>,
}

impl<SP: SessionParameters> PreprocessMessageTask<SP> {
    pub fn new(session_data: &Arc<SessionData<SP>>, message_id: MessageId<SP>, signed_value: SignedValue<SP>) -> Self {
        Self {
            session_data: session_data.clone(),
            message_id,
            signed_value,
        }
    }

    pub fn execute(self) -> TaskResult<SP> {
        // Before storing the value in the database, we check for the failures that are unattributable at this level.
        // In case of a failure all we can do is report the message ID and let the user deal with it
        // if their transport protocol allows it.

        // TODO (#60): reject messages from already banned nodes

        let source = self.signed_value.source().clone();

        // Check that the value is from one of the session participants.
        // If it is not, even if we detect something provably wrong with it,
        // the proof will be useless.
        if !self.session_data.participants.contains(self.signed_value.source()) {
            return TaskResult(TaskResultEnum::MessageError {
                message_id: self.message_id,
                description: format!("A sender {source:?} is not one of the participants"),
            });
        }

        // Check that the message is addressed to a correct destination (one that this node manages).
        // If it is not, it may be a replay attack.
        if !self
            .session_data
            .local_participants
            .contains(self.signed_value.metadata().destination())
        {
            return TaskResult(TaskResultEnum::MessageError {
                message_id: self.message_id,
                description: format!(
                    "A destination {:?} is not one of the local participants",
                    self.signed_value.metadata().destination()
                ),
            });
        }

        // Check that the value belongs to the this session.
        // If it does not, it may be a replay attack.
        if self.signed_value.metadata().session_id() != &self.session_data.id {
            return TaskResult(TaskResultEnum::MessageError {
                message_id: self.message_id,
                description: "Invalid session ID".into(),
            });
        }

        // Verify the value signature.
        let verified_value = match self.signed_value.verify(&self.message_id) {
            Ok(value) => value,
            Err(VerificationError::Runtime(error)) => return TaskResult(TaskResultEnum::RuntimeError(error)),
            Err(VerificationError::SignatureMismatch) => {
                return TaskResult(TaskResultEnum::MessageError {
                    message_id: self.message_id.clone(),
                    description: format!("Verification error for a message from {source:?}"),
                });
            }
        };

        let store_in = RemoteSignedTag::new_with_full_name(verified_value.metadata().full_name());
        let value = Value::new(verified_value);

        TaskResult(TaskResultEnum::Preprocessed {
            store_in: MappingTag::RemoteSigned(store_in),
            source,
            value,
        })
    }
}

impl<SP: SessionParameters> From<PreprocessMessageTask<SP>> for Task<SP> {
    fn from(source: PreprocessMessageTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::PreprocessMessage(source)))
    }
}

#[derive_where::derive_where(Debug)]
enum DeterministicTaskEnum<SP: SessionParameters> {
    ScalarUnattributable(ScalarUnattributableTask<SP>),
    ScalarUnattributableOptional(ScalarUnattributableOptionalTask<SP>),
    ElementUnattributable(ElementUnattributableTask<SP>),
    ElementSenderAttributable(ElementSenderAttributableTask<SP>),
    ElementSenderAttributableWithReveal(ElementSenderAttributableWithRevealTask<SP>),
    ElementThirdPartyAttributable(ElementThirdPartyAttributableTask<SP>),
    DeserializeElement(DeserializeElementTask<SP>),
    PreprocessMessage(PreprocessMessageTask<SP>),
}

/// An object encapsulating a deterministic task (one that does not require an RNG).
#[derive_where::derive_where(Debug)]
pub struct DeterministicTask<SP: SessionParameters>(DeterministicTaskEnum<SP>);

impl<SP: SessionParameters> DeterministicTask<SP> {
    /// Executes the task and returns a result to be passed back to the session.
    pub fn execute(self) -> TaskResult<SP> {
        match self.0 {
            DeterministicTaskEnum::ScalarUnattributable(task) => task.execute(),
            DeterministicTaskEnum::ScalarUnattributableOptional(task) => task.execute(),
            DeterministicTaskEnum::ElementUnattributable(task) => task.execute(),
            DeterministicTaskEnum::ElementSenderAttributable(task) => task.execute(),
            DeterministicTaskEnum::ElementSenderAttributableWithReveal(task) => task.execute(),
            DeterministicTaskEnum::ElementThirdPartyAttributable(task) => task.execute(),
            DeterministicTaskEnum::DeserializeElement(task) => task.execute(),
            DeterministicTaskEnum::PreprocessMessage(task) => task.execute(),
        }
    }
}

#[derive_where::derive_where(Debug)]
enum RandomizedTaskEnum<SP: SessionParameters> {
    ScalarUnattributable(RngScalarUnattributableTask<SP>),
    ElementUnattributable(RngElementUnattributableTask<SP>),
    SerializeAndSignElement(SerializeAndSignElementTask<SP>),
}

/// An object encapsulating a randomized task (one that requires and RNG).
#[derive_where::derive_where(Debug)]
pub struct RandomizedTask<SP: SessionParameters>(RandomizedTaskEnum<SP>);

impl<SP: SessionParameters> RandomizedTask<SP> {
    /// Executes the task and returns a result to be passed back to the session.
    pub fn execute(self, rng: &mut SP::Rng) -> TaskResult<SP> {
        match self.0 {
            RandomizedTaskEnum::ScalarUnattributable(task) => task.execute(rng),
            RandomizedTaskEnum::ElementUnattributable(task) => task.execute(rng),
            RandomizedTaskEnum::SerializeAndSignElement(task) => task.execute(rng),
        }
    }
}

/// A session task to be executed.
#[derive_where::derive_where(Debug)]
pub enum Task<SP: SessionParameters> {
    /// Send an outgoing message.
    Send(SendTask<SP>),
    /// Perform a dererministic computation.
    Deterministic(DeterministicTask<SP>),
    /// Perform a computation that needs access to an RNG.
    Randomized(RandomizedTask<SP>),
}

/// The result of executing a task, to be passed to [`Session::add_result`].
#[derive_where::derive_where(Debug)]
pub struct TaskResult<SP: SessionParameters>(TaskResultEnum<SP>);

impl<SP: SessionParameters> TaskResult<SP> {
    pub(crate) fn into_inner(self) -> TaskResultEnum<SP> {
        self.0
    }

    /// Bans a party internally, resulting in all of its messages and values calculated from them being discarded,
    /// and new messages ignored.
    pub fn ban_party(party_id: SP::Verifier, reason: String) -> Self {
        Self(TaskResultEnum::ExternalBan { party_id, reason })
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) enum TaskResultEnum<SP: SessionParameters> {
    NoActionNeeded,
    Sent {
        store_in: MappingTag,
        destination: SP::Verifier,
    },
    ComputedScalar {
        store_in: ScalarTag,
        result: Value,
    },
    ComputedMappingElement {
        store_in: MappingTag,
        index: SP::Verifier,
        result: Value,
    },
    Preprocessed {
        store_in: MappingTag,
        source: SP::Verifier,
        value: Value,
    },
    RuntimeError(RuntimeError),
    SpuriousError {
        store_in: AnyTag,
        error: SpuriousError,
    },
    SenderError {
        store_in: MappingTag,
        guilty_party: SP::Verifier,
        error: SenderError,
        on_error: OnError,
    },
    SenderErrorWithReveal {
        store_in: MappingTag,
        guilty_party: SP::Verifier,
        error: SenderErrorWithReveal<SP>,
        on_error: OnError,
    },
    ThirdPartyError {
        store_in: MappingTag,
        error: ThirdPartyError<SP>,
    },
    MessageError {
        message_id: MessageId<SP>,
        description: String,
    },
    SendError {
        destination: SP::Verifier,
    },
    ExternalBan {
        party_id: SP::Verifier,
        reason: String,
    },
}
