use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};

use super::{session::SessionData, storage::Storage};
use crate::{
    entities::{
        AnyTag, Args, ComputedMappingTag, ComputedScalarTag, DeserializeArgs, DeserializeFunction, LocalSignedBCTag,
        LocalSignedDMTag, MappingFunction, MappingTag, MaybeAttributableError, Message, MessageId, ReceivedTag,
        RemoteSignedTag, RuntimeError, ScalarFunction, ScalarTag, SenderAttributableMappingFunction,
        SenderAttributableWithRevealMappingFunction, SenderError, SenderErrorWithReveal, SentBCTag, SentDMTag,
        SerializeAndSignBCFunction, SerializeAndSignDMFunction, SerializeArgs, SessionId, SignedValue, SpuriousError,
        ThirdPartyAttributableMappingFunction, ThirdPartyAttributableScalarFunction, ThirdPartyError,
        UnattributableError, UnattributableMappingFunction, UnattributableMappingFunctionWithRng,
        UnattributableOptionalScalarFunction, UnattributableScalarFunction, UnattributableScalarFunctionWithRng, Value,
        VerificationError,
    },
    flat_representation::{
        ComputeDeserializeElementAction, ComputeMappingElementAction, ComputeScalarAction,
        ComputeSerializeAndSignElementAction, ComputeSerializeAndSignScalarAction, OnError, SendBCAction, SendDMAction,
    },
    traced_error::TraceableResult,
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

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = ScalarTag::Computed(self.store_in);
        match self.function.call(&self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedScalar { store_in, result }),
            Err(UnattributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => SessionUpdate(SessionUpdateEnum::SpuriousError {
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

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = ScalarTag::Computed(self.store_in);
        match self.function.call(&self.args) {
            Ok(result) => SessionUpdate(result.map_or_else(
                || SessionUpdateEnum::NoActionNeeded,
                |value| SessionUpdateEnum::ComputedScalar {
                    store_in,
                    result: value,
                },
            )),
            Err(error) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
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
pub(crate) struct ScalarThirdPartyAttributableTask<SP: SessionParameters> {
    store_in: ComputedScalarTag,
    function: ThirdPartyAttributableScalarFunction<SP>,
    args: Args<SP>,
}

impl<SP: SessionParameters> ScalarThirdPartyAttributableTask<SP> {
    pub fn new(
        store_in: ComputedScalarTag,
        function: ThirdPartyAttributableScalarFunction<SP>,
        args: Args<SP>,
    ) -> Self {
        Self {
            store_in,
            function,
            args,
        }
    }

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = ScalarTag::Computed(self.store_in);
        match self.function.call(&self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedScalar { store_in, result }),
            Err(MaybeAttributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => SessionUpdate(SessionUpdateEnum::ThirdPartyError {
                store_in: AnyTag::Scalar(store_in),
                error,
            }),
        }
    }
}

impl<SP: SessionParameters> From<ScalarThirdPartyAttributableTask<SP>> for Task<SP> {
    fn from(source: ScalarThirdPartyAttributableTask<SP>) -> Self {
        Self::Deterministic(DeterministicTask(DeterministicTaskEnum::ScalarThirdPartyAttributable(
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

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(UnattributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => SessionUpdate(SessionUpdateEnum::SpuriousError {
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

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => SessionUpdate(SessionUpdateEnum::SenderError {
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

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => {
                SessionUpdate(SessionUpdateEnum::SenderErrorWithReveal {
                    store_in,
                    guilty_party: self.index,
                    error,
                    on_error: self.on_error,
                })
            }
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

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(&self.index, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => SessionUpdate(SessionUpdateEnum::ThirdPartyError {
                store_in: AnyTag::Mapping(store_in),
                error,
            }),
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

    pub fn execute(self) -> SessionUpdate<SP> {
        let store_in = MappingTag::Received(self.store_in);
        match self.function.call(&self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(MaybeAttributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(MaybeAttributableError::Attributable(error)) => SessionUpdate(SessionUpdateEnum::SenderError {
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

    pub fn execute(self, rng: &mut SP::Rng) -> SessionUpdate<SP> {
        let store_in = ScalarTag::Computed(self.store_in);
        match self.function.call(rng, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedScalar { store_in, result }),
            Err(UnattributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => SessionUpdate(SessionUpdateEnum::SpuriousError {
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

    pub fn execute(self, rng: &mut SP::Rng) -> SessionUpdate<SP> {
        let store_in = MappingTag::Computed(self.store_in);
        match self.function.call(rng, &self.index, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(UnattributableError::Runtime(error)) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(UnattributableError::Spurious(error)) => SessionUpdate(SessionUpdateEnum::SpuriousError {
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
pub(crate) struct SerializeAndSignScalarTask<SP: SessionParameters> {
    store_in: LocalSignedBCTag,
    function: SerializeAndSignBCFunction<SP>,
    args: SerializeArgs<SP>,
}

impl<SP: SessionParameters> SerializeAndSignScalarTask<SP> {
    pub fn new(store_in: LocalSignedBCTag, function: SerializeAndSignBCFunction<SP>, args: SerializeArgs<SP>) -> Self {
        Self {
            store_in,
            function,
            args,
        }
    }

    pub fn execute(self, rng: &mut SP::Rng) -> SessionUpdate<SP> {
        let store_in = ScalarTag::LocalSigned(self.store_in);
        match self.function.call(rng, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedScalar { store_in, result }),
            Err(error) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
        }
    }
}

impl<SP: SessionParameters> From<SerializeAndSignScalarTask<SP>> for Task<SP> {
    fn from(source: SerializeAndSignScalarTask<SP>) -> Self {
        Self::Randomized(RandomizedTask(RandomizedTaskEnum::SerializeAndSignScalar(source)))
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct SerializeAndSignElementTask<SP: SessionParameters> {
    store_in: LocalSignedDMTag,
    function: SerializeAndSignDMFunction<SP>,
    index: SP::Verifier,
    args: SerializeArgs<SP>,
}

impl<SP: SessionParameters> SerializeAndSignElementTask<SP> {
    pub fn new(
        store_in: LocalSignedDMTag,
        function: SerializeAndSignDMFunction<SP>,
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

    pub fn execute(self, rng: &mut SP::Rng) -> SessionUpdate<SP> {
        let store_in = MappingTag::LocalSigned(self.store_in);
        match self.function.call(rng, &self.index, &self.args) {
            Ok(result) => SessionUpdate(SessionUpdateEnum::ComputedMappingElement {
                store_in,
                index: self.index,
                result,
            }),
            Err(error) => SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
        }
    }
}

impl<SP: SessionParameters> From<SerializeAndSignElementTask<SP>> for Task<SP> {
    fn from(source: SerializeAndSignElementTask<SP>) -> Self {
        Self::Randomized(RandomizedTask(RandomizedTaskEnum::SerializeAndSignElement(source)))
    }
}

/// An object enapsulating a task of sending message(s).
///
/// Can be converted into different types of messages, depending on what transport capabilities are available.
#[derive_where::derive_where(Debug)]
pub struct SendTask<SP: SessionParameters> {
    kind: SendTaskKind<SP>,
    direct_messages: BTreeMap<SP::Verifier, SignedValue<SP>>,
    broadcast_messages: Vec<(BTreeSet<SP::Verifier>, SignedValue<SP>)>,
}

#[derive_where::derive_where(Debug)]
enum SendTaskKind<SP: SessionParameters> {
    BroadcastMessage {
        store_in: SentBCTag,
    },
    DirectMessage {
        store_in: SentDMTag,
        destination: SP::Verifier,
    },
}

impl<SP: SessionParameters> SendTaskKind<SP> {
    fn into_update(self) -> SessionUpdate<SP> {
        SessionUpdate(match self {
            Self::BroadcastMessage { store_in } => SessionUpdateEnum::SentBC { store_in },
            Self::DirectMessage { store_in, destination } => SessionUpdateEnum::SentDM { store_in, destination },
        })
    }
}

impl<SP: SessionParameters> SendTask<SP> {
    pub(crate) fn from_send_bc_action(
        storage: &Storage<SP::Verifier>,
        action: SendBCAction<SP>,
    ) -> Result<Self, RuntimeError> {
        let value = storage
            .get_scalar(&ScalarTag::from(action.to_send))
            .or_with_context(|| format!("Failed to get the argument for `{}` from storage", action.store_in))?;
        let signed_value = value
            .downcast::<SignedValue<SP>>()
            .or_with_context(|| "Failed to downcast the value to be sent".into())?;
        Ok(Self {
            kind: SendTaskKind::BroadcastMessage {
                store_in: action.store_in,
            },
            direct_messages: BTreeMap::new(),
            broadcast_messages: vec![(action.destinations, signed_value)],
        })
    }

    pub(crate) fn from_send_dm_action(
        storage: &Storage<SP::Verifier>,
        action: SendDMAction<SP>,
    ) -> Result<Self, RuntimeError> {
        let value = storage
            .get_elem(&MappingTag::from(action.to_send), &action.destination)
            .or_with_context(|| format!("Failed to get the argument for `{}` from storage", action.store_in))?;
        let signed_value = value
            .downcast::<SignedValue<SP>>()
            .or_with_context(|| "Failed to downcast the value to be sent".into())?;
        Ok(Self {
            kind: SendTaskKind::DirectMessage {
                store_in: action.store_in,
                destination: action.destination.clone(),
            },
            direct_messages: [(action.destination, signed_value)].into(),
            broadcast_messages: Vec::new(),
        })
    }

    /// Converts the task into separated broadcasts and direct messages.
    #[expect(clippy::type_complexity)]
    pub fn into_bcs_and_dms(
        self,
    ) -> Result<
        (
            SessionUpdate<SP>,
            Vec<(BTreeSet<SP::Verifier>, Message<SP>)>,
            BTreeMap<SP::Verifier, Message<SP>>,
        ),
        RuntimeError,
    > {
        let update = self.kind.into_update();
        let dms = self
            .direct_messages
            .into_iter()
            .map(|(destination, value)| Message::new(vec![value]).map(|message| (destination, message)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let bcs = self
            .broadcast_messages
            .into_iter()
            .map(|(destinations, value)| Message::new(vec![value]).map(|message| (destinations, message)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((update, bcs, dms))
    }

    /// Converts the task into purely direct messages for each destination.
    #[expect(clippy::type_complexity)]
    pub fn into_dms(self) -> Result<(SessionUpdate<SP>, BTreeMap<SP::Verifier, Message<SP>>), RuntimeError> {
        let update = self.kind.into_update();
        let mut result = self
            .direct_messages
            .into_iter()
            .map(|(destination, value)| (destination, vec![value]))
            .collect::<BTreeMap<_, _>>();

        for (destinations, value) in self.broadcast_messages {
            for destination in destinations {
                result.entry(destination).or_default().push(value.clone());
            }
        }

        let dms = result
            .into_iter()
            .map(|(destination, values)| Message::new(values).map(|message| (destination, message)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok((update, dms))
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

    pub fn execute(self) -> SessionUpdate<SP> {
        // Before storing the value in the database, we check for the failures that are unattributable at this level.
        // In case of a failure all we can do is report the message ID and let the user deal with it
        // if their transport protocol allows it.

        // TODO (#60): reject messages from already banned nodes

        let source = self.signed_value.source().clone();

        // Check that the value is from one of the session participants.
        // If it is not, even if we detect something provably wrong with it,
        // the proof will be useless.
        if !self.session_data.participants.contains(self.signed_value.source()) {
            return SessionUpdate(SessionUpdateEnum::MessageError {
                message_id: self.message_id,
                description: format!("A sender {source:?} is not one of the participants"),
            });
        }

        // This is just a pre-check for the errors that are not attributable to the sender.
        // We will check that Some/None variant of the destination matches
        // whether we expected a broadcast or a direct message during deserealization,
        // because then the failure will be attributable and provable.
        if let Some(destination) = self.signed_value.metadata().destination() {
            // Check that the message is addressed to a correct destination (one that this node manages).
            // If it is not, it may be a replay attack.
            if !self.session_data.local_participants.contains(destination) {
                return SessionUpdate(SessionUpdateEnum::MessageError {
                    message_id: self.message_id,
                    description: format!(
                        "A destination {:?} is not one of the local participants",
                        self.signed_value.metadata().destination()
                    ),
                });
            }
        }

        // Check that the value belongs to the this session.
        // If it does not, it may be a replay attack.
        if self.signed_value.metadata().session_id() != &self.session_data.id {
            return SessionUpdate(SessionUpdateEnum::MessageError {
                message_id: self.message_id,
                description: "Invalid session ID".into(),
            });
        }

        // Verify the value signature.
        let verified_value = match self.signed_value.verify(&self.message_id) {
            Ok(value) => value,
            Err(VerificationError::Runtime(error)) => return SessionUpdate(SessionUpdateEnum::RuntimeError(error)),
            Err(VerificationError::SignatureMismatch) => {
                return SessionUpdate(SessionUpdateEnum::MessageError {
                    message_id: self.message_id.clone(),
                    description: format!("Verification error for a message from {source:?}"),
                });
            }
        };

        let store_in = RemoteSignedTag::new_with_full_name(verified_value.metadata().full_name());
        let value = Value::new(verified_value);

        SessionUpdate(SessionUpdateEnum::Preprocessed {
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
    ScalarThirdPartyAttributable(ScalarThirdPartyAttributableTask<SP>),
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
    pub fn execute(self) -> SessionUpdate<SP> {
        match self.0 {
            DeterministicTaskEnum::ScalarUnattributable(task) => task.execute(),
            DeterministicTaskEnum::ScalarUnattributableOptional(task) => task.execute(),
            DeterministicTaskEnum::ScalarThirdPartyAttributable(task) => task.execute(),
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
    SerializeAndSignScalar(SerializeAndSignScalarTask<SP>),
    SerializeAndSignElement(SerializeAndSignElementTask<SP>),
}

/// An object encapsulating a randomized task (one that requires and RNG).
#[derive_where::derive_where(Debug)]
pub struct RandomizedTask<SP: SessionParameters>(RandomizedTaskEnum<SP>);

impl<SP: SessionParameters> RandomizedTask<SP> {
    /// Executes the task and returns a result to be passed back to the session.
    pub fn execute(self, rng: &mut SP::Rng) -> SessionUpdate<SP> {
        match self.0 {
            RandomizedTaskEnum::ScalarUnattributable(task) => task.execute(rng),
            RandomizedTaskEnum::ElementUnattributable(task) => task.execute(rng),
            RandomizedTaskEnum::SerializeAndSignScalar(task) => task.execute(rng),
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

impl<SP: SessionParameters> Task<SP> {
    pub(crate) fn from_compute_scalar_action(
        session_id: &SessionId<SP>,
        session_verifier: &SP::Verifier,
        storage: &Storage<SP::Verifier>,
        action: ComputeScalarAction<SP>,
    ) -> Result<Self, RuntimeError> {
        let arg_values = storage
            .get_scalar_args(action.args)
            .or_with_context(|| format!("Failed to get the arguments for `{}` from storage", action.store_in))?;
        let args = Args::new(session_id, session_verifier, arg_values);

        Ok(match action.function {
            ScalarFunction::Unattributable(function) => {
                ScalarUnattributableTask::new(action.store_in, function, args).into()
            }
            ScalarFunction::UnattributableOptional(function) => {
                ScalarUnattributableOptionalTask::new(action.store_in, function, args).into()
            }
            ScalarFunction::UnattributableWithRng(function) => {
                RngScalarUnattributableTask::new(action.store_in, function, args).into()
            }
            ScalarFunction::ThirdPartyAttributable(function) => {
                ScalarThirdPartyAttributableTask::new(action.store_in, function, args).into()
            }
        })
    }

    pub(crate) fn from_compute_mapping_element_action(
        session_id: &SessionId<SP>,
        session_verifier: &SP::Verifier,
        storage: &Storage<SP::Verifier>,
        action: ComputeMappingElementAction<SP>,
    ) -> Result<Self, RuntimeError> {
        let arg_values = storage
            .get_scalar_or_mapping_args(&action.index, action.args)
            .or_with_context(|| format!("Failed to get the arguments for `{}` from storage", action.store_in))?;
        let args = Args::new(session_id, session_verifier, arg_values);
        Ok(match action.function {
            MappingFunction::Unattributable(function) => {
                ElementUnattributableTask::new(action.store_in, function, action.index, args).into()
            }
            MappingFunction::UnattributableWithRng(function) => {
                RngElementUnattributableTask::new(action.store_in, function, action.index, args).into()
            }
            MappingFunction::SenderAttributable(function) => {
                ElementSenderAttributableTask::new(action.store_in, function, action.index, args, action.on_error)
                    .into()
            }
            MappingFunction::SenderAttributableWithReveal(function) => ElementSenderAttributableWithRevealTask::new(
                action.store_in,
                function,
                action.index,
                args,
                action.on_error,
            )
            .into(),
            MappingFunction::ThirdPartyAttributable(function) => {
                ElementThirdPartyAttributableTask::new(action.store_in, function, action.index, args).into()
            }
        })
    }

    pub(crate) fn from_compute_serialize_and_sign_scalar_action(
        signer: &Arc<SP::Signer>,
        session_id: &SessionId<SP>,
        storage: &Storage<SP::Verifier>,
        action: ComputeSerializeAndSignScalarAction<SP>,
    ) -> Result<Self, RuntimeError> {
        let value = storage
            .get_scalar(&action.data)
            .or_with_context(|| format!("Failed to get the argument for `{}` from storage", action.data))?;

        let args = SerializeArgs::new(signer, session_id, action.message_name, action.serde_adapter, value);
        Ok(SerializeAndSignScalarTask::new(action.store_in, action.function, args).into())
    }

    pub(crate) fn from_compute_serialize_and_sign_element_action(
        signer: &Arc<SP::Signer>,
        session_id: &SessionId<SP>,
        storage: &Storage<SP::Verifier>,
        action: ComputeSerializeAndSignElementAction<SP>,
    ) -> Result<Self, RuntimeError> {
        let value = match action.data {
            AnyTag::Scalar(tag) => storage.get_scalar(&tag),
            AnyTag::Mapping(tag) => storage.get_elem(&tag, &action.index),
        }
        .or_with_context(|| format!("Failed to get the argument for `{}` from storage", action.store_in))?;

        let args = SerializeArgs::new(signer, session_id, action.message_name, action.serde_adapter, value);
        Ok(SerializeAndSignElementTask::new(action.store_in, action.function, action.index, args).into())
    }

    pub(crate) fn from_compute_deserialize_element_action(
        storage: &Storage<SP::Verifier>,
        action: ComputeDeserializeElementAction<SP>,
    ) -> Result<Self, RuntimeError> {
        let value = storage
            .get_elem(&MappingTag::from(action.data), &action.index)
            .or_with_context(|| format!("Failed to get the argument for `{}` from storage", action.store_in))?;
        let args = DeserializeArgs::new(&action.expected_senders, action.serde_adapter, value);
        Ok(DeserializeElementTask::new(action.store_in, action.function, action.index, args, action.on_error).into())
    }

    pub(crate) fn from_send_bc_action(
        storage: &Storage<SP::Verifier>,
        action: SendBCAction<SP>,
    ) -> Result<Self, RuntimeError> {
        Ok(SendTask::from_send_bc_action(storage, action)?.into())
    }

    pub(crate) fn from_send_dm_action(
        storage: &Storage<SP::Verifier>,
        action: SendDMAction<SP>,
    ) -> Result<Self, RuntimeError> {
        Ok(SendTask::from_send_dm_action(storage, action)?.into())
    }
}

/// The result of executing a task, to be passed to [`Session::with_update`].
#[derive_where::derive_where(Debug)]
pub struct SessionUpdate<SP: SessionParameters>(SessionUpdateEnum<SP>);

impl<SP: SessionParameters> SessionUpdate<SP> {
    pub(crate) fn into_inner(self) -> SessionUpdateEnum<SP> {
        self.0
    }

    /// Creates an update that, when applied, bans a party internally,
    /// resulting in all of its messages and values calculated from them being discarded,
    /// and new messages ignored.
    pub fn ban_party(party_id: SP::Verifier, reason: impl Into<String>) -> Self {
        Self(SessionUpdateEnum::ExternalBan {
            party_id,
            reason: reason.into(),
        })
    }

    /// Creates an update that adds a newly received message to the session.
    ///
    /// The user is expected to remember the passed `id` and associate it with the external sender,
    /// so that measure can be taken in case the message turns out to be malformed.
    pub fn add_message(id: MessageId<SP>, message: Message<SP>) -> Self {
        Self(SessionUpdateEnum::Received { id, message })
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) enum SessionUpdateEnum<SP: SessionParameters> {
    NoActionNeeded,
    SentBC {
        store_in: SentBCTag,
    },
    SentDM {
        store_in: SentDMTag,
        destination: SP::Verifier,
    },
    Received {
        id: MessageId<SP>,
        message: Message<SP>,
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
        store_in: AnyTag,
        error: ThirdPartyError<SP>,
    },
    MessageError {
        message_id: MessageId<SP>,
        description: String,
    },
    ExternalBan {
        party_id: SP::Verifier,
        reason: String,
    },
}
