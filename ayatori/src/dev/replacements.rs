use alloc::{boxed::Box, format, vec::Vec};
use core::fmt::{self, Debug};

use crate::{
    entities::{AnyTagRef, Args, Erasable, InfallibleScalarFunction, ScalarFunction, ScalarTag, Value},
    errors::LocalError,
    graph_representation::{Node, NodeKind},
    traits::SessionParameters,
};

pub struct Replacement<SP: SessionParameters> {
    tag: ScalarTag,
    kind: ReplacementEnum<SP>,
}

impl<SP: SessionParameters> Debug for Replacement<SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Replacement function for `{}`", self.tag)
    }
}

enum ReplacementEnum<SP: SessionParameters> {
    Scalar {
        #[allow(clippy::type_complexity)]
        function: Box<dyn Fn(&Value, Args<SP>) -> Result<Value, LocalError>>,
    },
}

impl<SP: SessionParameters> Replacement<SP> {
    pub fn compute_scalar<F, Ret>(name: &str, function: F) -> Self
    where
        Ret: Erasable,
        F: 'static + Fn(&Ret, Args<SP>) -> Result<Ret, LocalError>,
    {
        Self {
            // TODO (#61): support accessing nodes in subprotocols.
            tag: ScalarTag::computed(name),
            kind: ReplacementEnum::Scalar {
                function: Box::new(move |value, args| {
                    let typed_value = value.downcast_ref::<Ret>()?;
                    let typed_result = function(typed_value, args)?;
                    Ok(Value::new(typed_result))
                }),
            },
        }
    }

    pub(crate) fn apply(self, node: Node<SP>) -> Result<Node<SP>, LocalError> {
        let subnode = node
            .find_subnode(AnyTagRef::Scalar(&self.tag))
            .ok_or_else(|| LocalError::new("Node not found"))?;
        let new_subnode = match (subnode.kind(), self.kind) {
            (
                NodeKind::ComputeScalar {
                    store_in,
                    function,
                    args,
                },
                ReplacementEnum::Scalar {
                    function: replacement_function,
                },
            ) => {
                let new_function = if let ScalarFunction::Infallible(orig_function) = function {
                    let orig_function = orig_function.clone();
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
            _ => return Err(LocalError::new("Not supported")),
        };
        Ok(node.with_replaced_subnode(&subnode, &new_subnode))
    }
}
