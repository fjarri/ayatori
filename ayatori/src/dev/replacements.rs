use alloc::{format, sync::Arc, vec::Vec};
use core::fmt::{self, Debug};

use signature::rand_core::CryptoRngCore;

use crate::{
    entities::{
        AnyTag, Args, Erasable, FullName, InfallibleScalarFunction, MappingFunction, MappingTag, ScalarFunction,
        ScalarTag, SerdeAdapter, SerializeAndSignFunction, SignedValue, ThirdPartyAttributableMappingFunction,
        ThirdPartyError, Value,
    },
    errors::LocalError,
    execution::SessionId,
    graph_representation::{Node, NodeKind},
    traits::SessionParameters,
};

#[derive_where::derive_where(Clone)]
pub struct Replacement<SP: SessionParameters> {
    tag: AnyTag,
    kind: ReplacementEnum<SP>,
}

impl<SP: SessionParameters> Debug for Replacement<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Replacement function for `{}`", self.tag)
    }
}

#[derive_where::derive_where(Clone)]
#[allow(clippy::type_complexity)]
enum ReplacementEnum<SP: SessionParameters> {
    ComputeScalar {
        // TODO (#74): take `Value` by value.
        function: Arc<dyn Fn(&Value, Args<SP>) -> Result<Value, LocalError>>,
    },
    ComputeMapping {
        // TODO (#74): take `Value` by value.
        function: Arc<
            dyn Fn(Result<Value, ThirdPartyError<SP>>, &SP::Verifier, Args<SP>) -> Result<Value, ThirdPartyError<SP>>,
        >,
    },
    Message {
        function: Arc<
            dyn Fn(
                &mut dyn CryptoRngCore,
                &SP::Signer,
                &SP::Verifier,
                &SessionId<SP>,
                &Value,
                &FullName,
                &SerdeAdapter<SP::WireFormat>,
            ) -> Result<Value, LocalError>,
        >,
    },
}

impl<SP: SessionParameters> Replacement<SP> {
    pub fn compute_scalar<F, Ret>(name: &[&str], function: F) -> Result<Self, LocalError>
    where
        Ret: Erasable,
        F: 'static + Fn(&Ret, Args<SP>) -> Result<Ret, LocalError>,
    {
        let tag = ScalarTag::computed_with_full_name(FullName::new_with_prefix(name)?);
        Ok(Self {
            tag: AnyTag::Scalar(tag),
            kind: ReplacementEnum::ComputeScalar {
                function: Arc::new(move |value, args| {
                    let typed_value = value.downcast_ref::<Ret>()?;
                    let typed_result = function(typed_value, args)?;
                    Ok(Value::new(typed_result))
                }),
            },
        })
    }

    pub fn compute_mapping_third_party_attributable<F, Ret>(name: &[&str], function: F) -> Result<Self, LocalError>
    where
        Ret: Erasable,
        F: 'static + Fn(Result<&Ret, ThirdPartyError<SP>>, &SP::Verifier, Args<SP>) -> Result<Ret, ThirdPartyError<SP>>,
    {
        let tag = MappingTag::computed_with_full_name(FullName::new_with_prefix(name)?);
        Ok(Self {
            tag: AnyTag::Mapping(tag),
            kind: ReplacementEnum::ComputeMapping {
                function: Arc::new(move |maybe_value: Result<Value, ThirdPartyError<SP>>, id, args| {
                    // TODO (#74): this can be avoided if we return BoxedValue from functions,
                    // which can be unwrapped without cloning.
                    let typed_value = maybe_value
                        .as_ref()
                        .map_err(|err| (*err).clone())
                        .and_then(|value| value.downcast_ref::<Ret>().map_err(ThirdPartyError::from));
                    let typed_result = function(typed_value, id, args)?;
                    Ok(Value::new(typed_result))
                }),
            },
        })
    }

    pub fn message<F>(name: &[&str], function: F) -> Result<Self, LocalError>
    where
        F: 'static
            + Fn(
                &mut dyn CryptoRngCore,
                &SP::Signer,
                &SP::Verifier,
                &SessionId<SP>,
                &SignedValue<SP>,
                &FullName,
                &SerdeAdapter<SP::WireFormat>,
            ) -> Result<SignedValue<SP>, LocalError>,
    {
        let tag = MappingTag::signed_local_with_full_name(FullName::new_with_prefix(name)?);
        Ok(Self {
            tag: AnyTag::Mapping(tag),
            kind: ReplacementEnum::Message {
                function: Arc::new(
                    move |rng, signer, destination, session_id, value, message_name, serde_adapter| {
                        let typed_value = value.downcast_ref::<SignedValue<SP>>()?;
                        let typed_result = function(
                            rng,
                            signer,
                            destination,
                            session_id,
                            typed_value,
                            message_name,
                            serde_adapter,
                        )?;
                        Ok(Value::new(typed_result))
                    },
                ),
            },
        })
    }

    pub(crate) fn apply(&self, node: Node<SP>) -> Result<Node<SP>, LocalError> {
        let subnode = node
            .find_subnode(self.tag.as_ref())
            .ok_or_else(|| LocalError::new("Node not found"))?;
        let new_subnode = match (subnode.kind(), &self.kind) {
            (
                NodeKind::ComputeScalar {
                    store_in,
                    function,
                    args,
                },
                ReplacementEnum::ComputeScalar {
                    function: replacement_function,
                },
            ) => {
                let new_function = if let ScalarFunction::Infallible(orig_function) = function {
                    let orig_function = orig_function.clone();
                    let replacement_function = replacement_function.clone();
                    ScalarFunction::Infallible(InfallibleScalarFunction::new_pre_erased(
                        format!("[modified] {orig_function}"),
                        move |args| {
                            let orig_value = orig_function.call(args.clone())?;
                            replacement_function(&orig_value, args)
                        },
                    ))
                } else {
                    return Err(LocalError::new("Invalid function type"));
                };

                Node::new(NodeKind::ComputeScalar {
                    store_in: store_in.clone(),
                    function: new_function,
                    args: args
                        .iter()
                        .map(|(name, node)| (name.clone(), node.get_strong_ref()))
                        .collect(),
                })
                .with_dependencies(&subnode.dependencies().iter().collect::<Vec<_>>())?
            }
            (
                NodeKind::ComputeMapping {
                    store_in,
                    function,
                    args,
                    group,
                },
                ReplacementEnum::ComputeMapping {
                    function: replacement_function,
                },
            ) => {
                let new_function = if let MappingFunction::ThirdPartyAttributable {
                    function: orig_function,
                    verification,
                } = function
                {
                    let orig_function = orig_function.clone();
                    let replacement_function = replacement_function.clone();
                    MappingFunction::ThirdPartyAttributable {
                        function: ThirdPartyAttributableMappingFunction::new_pre_erased(
                            format!("[modified] {orig_function}"),
                            move |id, args| {
                                let orig_value = orig_function.call(id, args.clone());
                                replacement_function(orig_value, id, args)
                            },
                        ),
                        verification: verification.clone(),
                    }
                } else {
                    return Err(LocalError::new("Invalid function type"));
                };

                Node::new(NodeKind::ComputeMapping {
                    store_in: store_in.clone(),
                    function: new_function,
                    args: args
                        .iter()
                        .map(|(name, node)| (name.clone(), node.get_strong_ref()))
                        .collect(),
                    group: group.clone(),
                })
                .with_dependencies(&subnode.dependencies().iter().collect::<Vec<_>>())?
            }
            (
                NodeKind::SerializeAndSign {
                    store_in,
                    function,
                    data,
                    group,
                    serde_adapter,
                    message_name,
                },
                ReplacementEnum::Message {
                    function: replacement_function,
                },
            ) => {
                let function = function.clone();
                let replacement_function = replacement_function.clone();
                let new_function = SerializeAndSignFunction::new(
                    move |rng, signer, destination, session_id, value, message_name, serde_adapter| {
                        let orig_value =
                            function.call(rng, signer, destination, session_id, value, message_name, serde_adapter)?;
                        replacement_function(
                            rng,
                            signer,
                            destination,
                            session_id,
                            &orig_value,
                            message_name,
                            serde_adapter,
                        )
                    },
                );

                Node::new(NodeKind::SerializeAndSign {
                    store_in: store_in.clone(),
                    function: new_function,
                    data: data.get_strong_ref(),
                    group: group.clone(),
                    serde_adapter: serde_adapter.clone(),
                    message_name: message_name.clone(),
                })
                .with_dependencies(&subnode.dependencies().iter().collect::<Vec<_>>())?
            }
            _ => return Err(LocalError::new("Not supported")),
        };
        Ok(node.with_replaced_subnode(&subnode, &new_subnode))
    }
}
