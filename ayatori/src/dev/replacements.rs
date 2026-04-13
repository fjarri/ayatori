use alloc::{format, sync::Arc};
use core::fmt::{self, Debug};

use signature::rand_core::CryptoRngCore;

use crate::{
    entities::{
        AnyTag, Args, ComputedMappingTag, ComputedScalarTag, Erasable, FullName, LocalSignedTag, MappingTag,
        RuntimeError, ScalarFunction, ScalarTag, SerializeAndSignFunction, SerializeArgs, SignedValue,
        SimpleMappingFunction, ThirdPartyAttributableError, ThirdPartyAttributableMappingFunction, UnattributableError,
        UnattributableMappingFunction, UnattributableScalarFunction, Value,
    },
    graph_representation::{AnyNode, ComputeMappingKind, GeneralizedNode, OutputNode, ShallowClone},
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
                            .map_err(Clone::clone)
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

    pub(crate) fn apply(&self, node: &OutputNode<SP>) -> Result<OutputNode<SP>, RuntimeError> {
        let subnode = AnyNode::from(node.get_strong_ref())
            .find_subnode(self.tag.as_ref())
            .ok_or_else(|| RuntimeError::new("Node not found"))?;
        let new_subnode = match (&subnode, &self.kind) {
            (
                AnyNode::ComputeScalar(node),
                ReplacementEnum::ComputeScalar {
                    function: replacement_function,
                },
            ) => {
                let new_function = if let ScalarFunction::Unattributable(orig_function) = &node.as_ref().function {
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

                AnyNode::from(node.get_strong_ref().mutated(|inner| {
                    let mut inner = inner.shallow_clone();
                    inner.function = new_function;
                    inner
                }))
            }
            (
                AnyNode::ComputeMapping(node),
                ReplacementEnum::ComputeMapping {
                    function: replacement_function,
                },
            ) => {
                let new_kind = if let ComputeMappingKind::Simple { function } = &node.as_ref().kind
                    && let SimpleMappingFunction::Unattributable(orig_function) = function
                {
                    let orig_function = orig_function.clone();
                    let replacement_function = replacement_function.clone();
                    let new_function =
                        SimpleMappingFunction::Unattributable(UnattributableMappingFunction::new_with_name(
                            format!("[modified] {orig_function}"),
                            move |id, args| {
                                let orig_value = orig_function.call(id, args)?;
                                replacement_function(orig_value, id, args)
                            },
                        ));
                    ComputeMappingKind::Simple { function: new_function }
                } else {
                    return Err(RuntimeError::new("Invalid function type"));
                };

                AnyNode::from(node.get_strong_ref().mutated(|inner| {
                    let mut inner = inner.shallow_clone();
                    inner.kind = new_kind;
                    inner
                }))
            }
            (
                AnyNode::ComputeMapping(node),
                ReplacementEnum::ComputeMappingThirdPartyAttributable {
                    function: replacement_function,
                },
            ) => {
                let new_kind = if let ComputeMappingKind::ThirdPartyAttributable {
                    function: orig_function,
                    verification,
                } = &node.as_ref().kind
                {
                    let orig_function = orig_function.clone();
                    let replacement_function = replacement_function.clone();
                    ComputeMappingKind::ThirdPartyAttributable {
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

                AnyNode::from(node.get_strong_ref().mutated(|inner| {
                    let mut inner = inner.shallow_clone();
                    inner.kind = new_kind;
                    inner
                }))
            }
            (
                AnyNode::SerializeAndSign(node),
                ReplacementEnum::Message {
                    function: replacement_function,
                },
            ) => {
                let function = node.as_ref().function.clone();
                let replacement_function = replacement_function.clone();
                let new_function = SerializeAndSignFunction::new(move |rng, destination, args| {
                    let orig_value = function.call(rng, destination, args)?;
                    replacement_function(rng, orig_value, destination, args)
                });

                AnyNode::from(node.get_strong_ref().mutated(|inner| {
                    let mut inner = inner.shallow_clone();
                    inner.function = new_function;
                    inner
                }))
            }
            _ => return Err(RuntimeError::new("Not supported")),
        };
        Ok(AnyNode::from(node.get_strong_ref())
            .with_replaced_subnode(&subnode, &new_subnode)
            .try_into()
            .expect("the root node type did not change"))
    }
}
