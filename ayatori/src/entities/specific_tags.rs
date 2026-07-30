use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use serde::{Deserialize, Serialize};

use super::{
    errors::UnionCastError,
    union_tags::{AnyTag, AnyTagRef, MappingTag, MappingTagRef, ScalarTag, ScalarTagRef},
};

#[cfg(feature = "dev")]
use super::errors::RuntimeError;

/// A fully qualified name associated with a node in a graph (or, in other terms,
/// the name of the slot the node's result will be stored in).
///
/// Contains the name of the slot itself and all the prefixes
/// added when the graph is included as a subgraph in a larger graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FullName {
    prefix: Vec<String>,
    name: String,
}

impl FullName {
    pub(crate) fn new(name: &str) -> Self {
        Self {
            prefix: Vec::new(),
            name: name.to_string(),
        }
    }

    /// Creates a new name with optional prefixes (to recreate the names generated for nested protocols).
    ///
    /// The name of the tag is the last element of `prefix_and_name`,
    /// so it must be non-empty.
    #[cfg(feature = "dev")]
    pub fn new_with_prefix(prefix_and_name: &[&str]) -> Result<Self, RuntimeError> {
        let mut names = prefix_and_name.iter().map(ToString::to_string).collect::<Vec<String>>();
        let name = names
            .pop()
            .ok_or_else(|| RuntimeError::new("The name must have at least one element"))?;
        Ok(Self { prefix: names, name })
    }

    pub(crate) fn with_added_prefix(self, prefix: &str) -> Self {
        let mut full_prefix = self.prefix;
        full_prefix.push(prefix.to_string());
        Self {
            prefix: full_prefix,
            name: self.name,
        }
    }
}

impl Display for FullName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for prefix in &self.prefix {
            write!(f, "{prefix}/")?;
        }
        write!(f, "{}", self.name)
    }
}

macro_rules! define_tag_type {
    (
        $(#[$meta:meta])*
        $display:literal
        $type_name:ident, $anytag_variant:ident($category:ident/$category_ref:ident :: $category_variant:ident)
        $(, $new:ident)?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        pub(crate) struct $type_name(FullName);

        impl $type_name {
            pub fn with_added_prefix(self, prefix: &str) -> Self {
                Self(self.0.with_added_prefix(prefix))
            }
        }

        impl From<$type_name> for $category {
            fn from(source: $type_name) -> Self {
                Self::$category_variant(source)
            }
        }

        impl From<$type_name> for AnyTag {
            fn from(source: $type_name) -> Self {
                Self::$anytag_variant($category::from(source))
            }
        }

        impl TryFrom<$category> for $type_name {
            type Error = UnionCastError;
            fn try_from(source: $category) -> Result<Self, Self::Error> {
                match source {
                    $category::$category_variant(tag) => Ok(tag),
                    _ => Err(UnionCastError)
                }
            }
        }

        impl TryFrom<AnyTag> for $type_name {
            type Error = UnionCastError;
            fn try_from(source: AnyTag) -> Result<Self, Self::Error> {
                Self::try_from($category::try_from(source)?)
            }
        }

        impl<'a> From<&'a $type_name> for $category_ref<'a> {
            fn from(source: &'a $type_name) -> Self {
                Self::$category_variant(source)
            }
        }

        impl<'a> From<&'a $type_name> for AnyTagRef<'a> {
            fn from(source: &'a $type_name) -> Self {
                Self::$anytag_variant($category_ref::from(source))
            }
        }

        impl Display for $type_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, $display, self.0)
            }
        }

        define_tag_type!(@maybe_new $type_name $(, $new)?);
    };

    (@maybe_new $type_name:ident, new) => {
        impl $type_name {
            pub fn new(name: &str) -> Self {
                Self(FullName::new(name))
            }
        }
    };

    (@maybe_new $type_name:ident) => {};
}

define_tag_type!(
    /// A locally computed value coming from an explicit computation/verification node
    /// (not from serialization/deserialization).
    /// The name of the tag will come from what the user provided when creating the node.
    /// The contents are of some user type.
    "{0}"
    ComputedScalarTag, Scalar(ScalarTag/ScalarTagRef::Computed), new
);

define_tag_type!(
    /// Two merged scalar values; can contain either one or both of them.
    "merged({0})"
    MergedScalarTag, Scalar(ScalarTag/ScalarTagRef::Merged), new
);

define_tag_type!(
    /// Scalar argument to a protocol.
    "arg({0})"
    ScalarArgumentTag, Scalar(ScalarTag/ScalarTagRef::Argument), new
);

define_tag_type!(
    /// A locally computed value coming from an explicit computation/verification node
    /// (not from serialization/deserialization).
    /// The name of the tag will come from what the user provided when creating the node.
    /// The contents are of some user type.
    "{0}"
    ComputedMappingTag, Mapping(MappingTag/MappingTagRef::Computed), new
);

define_tag_type!(
    /// A marker indicating that a value was broadcasted.
    /// The name of the tag will come from the protocol message name.
    /// The contents of the value are `()`.
    "sent-bc({0})"
    SentBCTag, Scalar(ScalarTag/ScalarTagRef::Sent)
);

define_tag_type!(
    /// A marker indicating that a value was sent out.
    /// The name of the tag will come from the protocol message name.
    /// The contents of the value are `()`.
    "sent-dm({0})"
    SentDMTag, Mapping(MappingTag/MappingTagRef::Sent)
);

define_tag_type!(
    /// A value deserialized from a message received from another node.
    /// The name of the tag will come from the protocol message name.
    /// The contents are of some user type.
    "received({0})"
    ReceivedTag, Mapping(MappingTag/MappingTagRef::Received)
);

define_tag_type!(
    /// A signed broadcast value + metadata originating from this node.
    /// The name of the tag will come from the protocol message name.
    /// The contents are `SignedValue`.
    "signed-bc-local({0})"
    LocalSignedBCTag, Scalar(ScalarTag/ScalarTagRef::LocalSigned), new
);

define_tag_type!(
    /// A signed direct message value + metadata originating from this node.
    /// The name of the tag will come from the protocol message name.
    /// The contents are `SignedValue`.
    "signed-dm-local({0})"
    LocalSignedDMTag, Mapping(MappingTag/MappingTagRef::LocalSigned), new
);

define_tag_type!(
    /// A signed value + metadata originating from another node.
    /// The name of the tag will come from the protocol message name.
    /// The contents are `SignedValue`.
    "signed-remote({0})"
    RemoteSignedTag, Mapping(MappingTag/MappingTagRef::RemoteSigned), new
);

impl ComputedScalarTag {
    #[cfg(feature = "dev")]
    pub fn new_with_full_name(full_name: FullName) -> Self {
        Self(full_name)
    }
}

impl ComputedMappingTag {
    #[cfg(feature = "dev")]
    pub fn new_with_full_name(full_name: FullName) -> Self {
        Self(full_name)
    }
}

impl SentDMTag {
    pub fn to_collected(&self) -> CollectedTag {
        CollectedTag::new(MappingTag::from(self.clone()), None)
    }
}

impl LocalSignedBCTag {
    #[cfg(feature = "dev")]
    pub fn new_with_full_name(full_name: FullName) -> Self {
        Self(full_name)
    }

    pub fn to_broadcast_message_sent(&self) -> SentBCTag {
        SentBCTag(self.0.clone())
    }
}

impl LocalSignedDMTag {
    #[cfg(feature = "dev")]
    pub fn new_with_full_name(full_name: FullName) -> Self {
        Self(full_name)
    }

    pub fn to_direct_message_sent(&self) -> SentDMTag {
        SentDMTag(self.0.clone())
    }
}

impl RemoteSignedTag {
    pub fn new_with_full_name(full_name: &FullName) -> Self {
        Self(full_name.clone())
    }

    pub fn to_received(&self) -> ReceivedTag {
        ReceivedTag(self.0.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct CollectedTag {
    collected_from: MappingTag,
    /// A part of the tag that is used to distinguish between several nodes collected from the same mapping node.
    disambiguator: Option<String>,
}

impl Display for CollectedTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "collected({}", self.collected_from)?;
        if let Some(disambiguator) = &self.disambiguator {
            write!(f, ", {disambiguator}")?;
        }
        write!(f, ")")
    }
}

impl CollectedTag {
    pub(crate) fn new(collected_from: MappingTag, disambiguator: Option<&str>) -> Self {
        Self {
            collected_from,
            disambiguator: disambiguator.map(String::from),
        }
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self {
            collected_from: self.collected_from.with_added_prefix(prefix),
            disambiguator: self.disambiguator,
        }
    }
}

impl From<CollectedTag> for ScalarTag {
    fn from(source: CollectedTag) -> Self {
        Self::Collected(source)
    }
}

impl From<CollectedTag> for AnyTag {
    fn from(source: CollectedTag) -> Self {
        Self::Scalar(ScalarTag::from(source))
    }
}

impl<'a> From<&'a CollectedTag> for ScalarTagRef<'a> {
    fn from(source: &'a CollectedTag) -> Self {
        Self::Collected(source)
    }
}

impl<'a> From<&'a CollectedTag> for AnyTagRef<'a> {
    fn from(source: &'a CollectedTag) -> Self {
        Self::Scalar(ScalarTagRef::from(source))
    }
}
