use alloc::{boxed::Box, format, vec::Vec};

use crate::error::LocalError;
use crate::protocol::{
    Args, Erasable, InfallibleScalarFunction, Node, NodeKind, ScalarFunction, SessionParameters, Tag, Value,
};

// TODO: support several replacements with a shared state

pub struct Replacement<SP: SessionParameters> {
    tag: Tag,
    kind: ReplacementEnum<SP>,
}

enum ReplacementEnum<SP: SessionParameters> {
    Scalar {
        function: Box<dyn Fn(&Value, Args<SP>) -> Result<Value, LocalError>>,
    },
}

impl<SP: SessionParameters> Replacement<SP> {
    pub fn new() -> Self {
        todo!()
    }

    pub fn compute_scalar<F, Ret>(name: &str, function: F) -> Self
    where
        Ret: Erasable,
        F: 'static + Fn(&Ret, Args<SP>) -> Result<Ret, LocalError>,
    {
        Self {
            // TODO: support accessing nodes in subprotocols.
            tag: Tag::computed(name),
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
        for subnode in node.flattened() {
            if subnode.store_in() == &self.tag {
                let new_subnode = match (subnode.kind(), self.kind) {
                    (
                        NodeKind::ComputeScalar { function, args },
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

                        Node::new(
                            self.tag.clone(),
                            NodeKind::ComputeScalar {
                                function: new_function,
                                args: args
                                    .iter()
                                    .map(|(name, node)| (name.clone(), node.get_strong_ref()))
                                    .collect(),
                            },
                        )
                        .with_dependencies(&subnode.dependencies().iter().collect::<Vec<_>>())
                    }
                    _ => return Err(LocalError::new("Not supported")),
                };
                return Ok(node.with_replaced_subnode(&subnode, &new_subnode));
            }
        }
        Err(LocalError::new("Node not found"))
    }
}
