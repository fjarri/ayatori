use alloc::{format, sync::Arc, vec::Vec};
use core::fmt::{self, Debug};

use signature::rand_core::CryptoRngCore;

use crate::{
    entities::{
        AnyTag, Args, ComputedMappingTag, ComputedScalarTag, Erasable, FullName, LocalSignedTag, MappingFunction,
        MappingTag, RuntimeError, ScalarFunction, ScalarTag, SerializeAndSignFunction, SerializeArgs, SignedValue,
        ThirdPartyAttributableError, ThirdPartyAttributableMappingFunction, UnattributableError,
        UnattributableMappingFunction, UnattributableScalarFunction, Value,
    },
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
        function: Arc<dyn Fn(Value, &Args<SP>) -> Result<Value, UnattributableError>>,
    },
    ComputeMapping {
        function: Arc<dyn Fn(Value, &SP::Verifier, &Args<SP>) -> Result<Value, UnattributableError>>,
    },
    ComputeMappingThirdPartyAttributable {
        function: Arc<
            dyn Fn(
                Result<Value, ThirdPartyAttributableError<SP>>,
                &SP::Verifier,
                &Args<SP>,
            ) -> Result<Value, ThirdPartyAttributableError<SP>>,
        >,
    },
    Message {
        function: Arc<
            dyn Fn(&mut dyn CryptoRngCore, Value, &SP::Verifier, &SerializeArgs<SP>) -> Result<Value, RuntimeError>,
        >,
    },
}

impl<SP: SessionParameters> Replacement<SP> {
    pub fn compute_scalar<F, Ret>(name: &[&str], function: F) -> Result<Self, RuntimeError>
    where
        Ret: Erasable,
        F: 'static + Fn(&Ret, &Args<SP>) -> Result<Ret, UnattributableError>,
    {
        let tag = ComputedScalarTag::new_with_full_name(FullName::new_with_prefix(name)?);
        Ok(Self {
            tag: AnyTag::Scalar(ScalarTag::Computed(tag)),
            kind: ReplacementEnum::ComputeScalar {
                function: Arc::new(move |value, args| {
                    let typed_value = value.downcast_ref::<Ret>()?;
                    let typed_result = function(typed_value, args)?;
                    Ok(Value::new(typed_result))
                }),
            },
        })
    }

    pub fn compute_mapping<F, Ret>(name: &[&str], function: F) -> Result<Self, RuntimeError>
    where
        Ret: Erasable,
        F: 'static + Fn(&Ret, &SP::Verifier, &Args<SP>) -> Result<Ret, UnattributableError>,
    {
        let tag = ComputedMappingTag::new_with_full_name(FullName::new_with_prefix(name)?);
        Ok(Self {
            tag: AnyTag::Mapping(MappingTag::Computed(tag)),
            kind: ReplacementEnum::ComputeMapping {
                function: Arc::new(move |value: Value, id, args| {
                    let typed_value = value.downcast_ref::<Ret>()?;
                    let typed_result = function(typed_value, id, args)?;
                    Ok(Value::new(typed_result))
                }),
            },
        })
    }

    pub fn compute_mapping_third_party_attributable<F, Ret>(name: &[&str], function: F) -> Result<Self, RuntimeError>
    where
        Ret: Erasable,
        F: 'static
            + Fn(
                Result<&Ret, ThirdPartyAttributableError<SP>>,
                &SP::Verifier,
                &Args<SP>,
            ) -> Result<Ret, ThirdPartyAttributableError<SP>>,
    {
        let tag = ComputedMappingTag::new_with_full_name(FullName::new_with_prefix(name)?);
        Ok(Self {
            tag: AnyTag::Mapping(MappingTag::Computed(tag)),
            kind: ReplacementEnum::ComputeMappingThirdPartyAttributable {
                function: Arc::new(
                    move |maybe_value: Result<Value, ThirdPartyAttributableError<SP>>, id, args| {
                        let typed_value = maybe_value
                            .as_ref()
                            .map_err(|err| err.clone())
                            .and_then(|value| value.downcast_ref::<Ret>().map_err(ThirdPartyAttributableError::from));
                        let typed_result = function(typed_value, id, args)?;
                        Ok(Value::new(typed_result))
                    },
                ),
            },
        })
    }

    pub fn message<F>(name: &[&str], function: F) -> Result<Self, RuntimeError>
    where
        F: 'static
            + Fn(
                &mut dyn CryptoRngCore,
                &SignedValue<SP>,
                &SP::Verifier,
                &SerializeArgs<SP>,
            ) -> Result<SignedValue<SP>, RuntimeError>,
    {
        let tag = LocalSignedTag::new_with_full_name(FullName::new_with_prefix(name)?);
        Ok(Self {
            tag: AnyTag::Mapping(MappingTag::LocalSigned(tag)),
            kind: ReplacementEnum::Message {
                function: Arc::new(move |rng, orig_value, destination, args| {
                    let typed_value = orig_value.downcast_ref::<SignedValue<SP>>()?;
                    let typed_result = function(rng, typed_value, destination, args)?;
                    Ok(Value::new(typed_result))
                }),
            },
        })
    }

    pub(crate) fn apply(&self, node: Node<SP>) -> Result<Node<SP>, RuntimeError> {
        let subnode = node
            .find_subnode(self.tag.as_ref())
            .ok_or_else(|| RuntimeError::new("Node not found"))?;
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
                let new_function = if let ScalarFunction::Unattributable(orig_function) = function {
                    let orig_function = orig_function.clone();
                    let replacement_function = replacement_function.clone();
                    ScalarFunction::Unattributable(UnattributableScalarFunction::new_with_name(
                        format!("[modified] {orig_function}"),
                        move |args| {
                            let orig_value = orig_function.call(args)?;
                            replacement_function(orig_value, args)
                        },
                    ))
                } else {
                    return Err(RuntimeError::new("Invalid function type"));
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
                },
                ReplacementEnum::ComputeMapping {
                    function: replacement_function,
                },
            ) => {
                let new_function = if let MappingFunction::Unattributable(orig_function) = function {
                    let orig_function = orig_function.clone();
                    let replacement_function = replacement_function.clone();
                    MappingFunction::Unattributable(UnattributableMappingFunction::new_with_name(
                        format!("[modified] {orig_function}"),
                        move |id, args| {
                            let orig_value = orig_function.call(id, args)?;
                            replacement_function(orig_value, id, args)
                        },
                    ))
                } else {
                    return Err(RuntimeError::new("Invalid function type"));
                };

                Node::new(NodeKind::ComputeMapping {
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
                },
                ReplacementEnum::ComputeMappingThirdPartyAttributable {
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
                        function: ThirdPartyAttributableMappingFunction::new_with_name(
                            format!("[modified] {orig_function}"),
                            move |id, args| {
                                let orig_value = orig_function.call(id, args);
                                replacement_function(orig_value, id, args)
                            },
                        ),
                        verification: verification.clone(),
                    }
                } else {
                    return Err(RuntimeError::new("Invalid function type"));
                };

                Node::new(NodeKind::ComputeMapping {
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
                NodeKind::SerializeAndSign {
                    store_in,
                    function,
                    data,
                    serde_adapter,
                    message_name,
                },
                ReplacementEnum::Message {
                    function: replacement_function,
                },
            ) => {
                let function = function.clone();
                let replacement_function = replacement_function.clone();
                let new_function = SerializeAndSignFunction::new(move |rng, destination, args| {
                    let orig_value = function.call(rng, destination, args)?;
                    replacement_function(rng, orig_value, destination, args)
                });

                Node::new(NodeKind::SerializeAndSign {
                    store_in: store_in.clone(),
                    function: new_function,
                    data: data.get_strong_ref(),
                    serde_adapter: serde_adapter.clone(),
                    message_name: message_name.clone(),
                })
                .with_dependencies(&subnode.dependencies().iter().collect::<Vec<_>>())?
            }
            _ => return Err(RuntimeError::new("Not supported")),
        };
        Ok(node.with_replaced_subnode(&subnode, &new_subnode))
    }
}
