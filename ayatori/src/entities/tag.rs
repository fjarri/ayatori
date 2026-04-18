use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use serde::{Deserialize, Serialize};

#[cfg(feature = "dev")]
use super::errors::RuntimeError;

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

    #[cfg(feature = "dev")]
    pub(crate) fn new_with_prefix(prefix_and_name: &[&str]) -> Result<Self, RuntimeError> {
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

/// A locally computed value coming from an explicit computation/verification node
/// (not from serialization/deserialization).
/// The name of the tag will come from what the user provided when creating the node.
/// The contents are of some user type.
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("{0}")]
pub(crate) struct ComputedScalarTag(pub(crate) FullName);

impl ComputedScalarTag {
    pub fn new(name: &str) -> Self {
        Self(FullName::new(name))
    }

    #[cfg(feature = "dev")]
    pub fn new_with_full_name(full_name: FullName) -> Self {
        Self(full_name)
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

/// Two merged scalar values; can contain either one or both of them.
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("merged({0})")]
pub(crate) struct MergedScalarTag(pub(crate) FullName);

impl MergedScalarTag {
    pub fn new(name: &str) -> Self {
        Self(FullName::new(name))
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("arg({0})")]
pub(crate) struct ScalarArgumentTag(pub(crate) FullName);

impl ScalarArgumentTag {
    pub fn new(name: &str) -> Self {
        Self(FullName::new(name))
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("collected({0})")]
pub(crate) struct CollectedTag(pub(crate) MappingTag);

impl CollectedTag {
    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

/// A locally computed value coming from an explicit computation/verification node
/// (not from serialization/deserialization).
/// The name of the tag will come from what the user provided when creating the node.
/// The contents are of some user type.
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("{0}")]
pub(crate) struct ComputedMappingTag(pub(crate) FullName);

impl ComputedMappingTag {
    pub fn new(name: &str) -> Self {
        Self(FullName::new(name))
    }

    #[cfg(feature = "dev")]
    pub fn new_with_full_name(full_name: FullName) -> Self {
        Self(full_name)
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

/// A marker indicating that a value was sent out.
/// The name of the tag will come from the protocol message name.
/// The contents of the value are `()`.
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("sent({0})")]
pub(crate) struct SentTag(pub(crate) FullName);

impl SentTag {
    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

/// A value deserialized from a message received from another node.
/// The name of the tag will come from the protocol message name.
/// The contents are of some user type.
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("received({0})")]
pub(crate) struct ReceivedTag(pub(crate) FullName);

impl ReceivedTag {
    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

/// A signed value + metadata originating from this node.
/// The name of the tag will come from the protocol message name.
/// The contents are `SignedValue`.
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("signed-local({0})")]
pub(crate) struct LocalSignedTag(pub(crate) FullName);

impl LocalSignedTag {
    pub fn new(name: &str) -> Self {
        Self(FullName::new(name))
    }

    #[cfg(feature = "dev")]
    pub fn new_with_full_name(full_name: FullName) -> Self {
        Self(full_name)
    }

    pub fn to_sent(&self) -> SentTag {
        SentTag(self.0.clone())
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

/// A signed value + metadata originating from another node.
/// The name of the tag will come from the protocol message name.
/// The contents are `SignedValue`.
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[displaydoc("signed-remote({0})")]
pub(crate) struct RemoteSignedTag(pub(crate) FullName);

impl RemoteSignedTag {
    pub fn new(name: &str) -> Self {
        Self(FullName::new(name))
    }

    pub fn new_with_full_name(full_name: &FullName) -> Self {
        Self(full_name.clone())
    }

    pub fn to_received(&self) -> ReceivedTag {
        ReceivedTag(self.0.clone())
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }
}

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ScalarTag {
    #[displaydoc("{0}")]
    Computed(ComputedScalarTag),
    #[displaydoc("{0}")]
    Merged(MergedScalarTag),
    #[displaydoc("{0}")]
    Argument(ScalarArgumentTag),
    #[displaydoc("{0}")]
    Collected(CollectedTag),
}

impl ScalarTag {
    #[cfg(feature = "dev")]
    pub fn as_ref(&self) -> ScalarTagRef<'_> {
        match self {
            Self::Computed(tag) => ScalarTagRef::Computed(tag),
            Self::Merged(tag) => ScalarTagRef::Merged(tag),
            Self::Argument(tag) => ScalarTagRef::Argument(tag),
            Self::Collected(tag) => ScalarTagRef::Collected(tag),
        }
    }
}

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum MappingTag {
    #[displaydoc("{0}")]
    Computed(ComputedMappingTag),
    #[displaydoc("{0}")]
    Sent(SentTag),
    #[displaydoc("{0}")]
    Received(ReceivedTag),
    #[displaydoc("{0}")]
    LocalSigned(LocalSignedTag),
    #[displaydoc("{0}")]
    RemoteSigned(RemoteSignedTag),
}

impl MappingTag {
    pub fn as_ref(&self) -> MappingTagRef<'_> {
        match self {
            Self::Computed(tag) => MappingTagRef::Computed(tag),
            Self::Sent(tag) => MappingTagRef::Sent(tag),
            Self::Received(tag) => MappingTagRef::Received(tag),
            Self::LocalSigned(tag) => MappingTagRef::LocalSigned(tag),
            Self::RemoteSigned(tag) => MappingTagRef::RemoteSigned(tag),
        }
    }
}

impl MappingTag {
    pub fn with_added_prefix(self, prefix: &str) -> Self {
        match self {
            Self::Computed(tag) => Self::Computed(tag.with_added_prefix(prefix)),
            Self::Sent(tag) => Self::Sent(tag.with_added_prefix(prefix)),
            Self::Received(tag) => Self::Received(tag.with_added_prefix(prefix)),
            Self::LocalSigned(tag) => Self::LocalSigned(tag.with_added_prefix(prefix)),
            Self::RemoteSigned(tag) => Self::RemoteSigned(tag.with_added_prefix(prefix)),
        }
    }
}

#[derive(displaydoc::Display, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalarTagRef<'a> {
    #[displaydoc("{0}")]
    Computed(&'a ComputedScalarTag),
    #[displaydoc("{0}")]
    Merged(&'a MergedScalarTag),
    #[displaydoc("{0}")]
    Argument(&'a ScalarArgumentTag),
    #[displaydoc("{0}")]
    Collected(&'a CollectedTag),
}

impl ScalarTagRef<'_> {
    pub fn to_owned(self) -> ScalarTag {
        match self {
            Self::Computed(tag) => ScalarTag::Computed((*tag).clone()),
            Self::Merged(tag) => ScalarTag::Merged((*tag).clone()),
            Self::Argument(tag) => ScalarTag::Argument((*tag).clone()),
            Self::Collected(tag) => ScalarTag::Collected((*tag).clone()),
        }
    }
}

#[derive(displaydoc::Display, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingTagRef<'a> {
    #[displaydoc("{0}")]
    Computed(&'a ComputedMappingTag),
    #[displaydoc("{0}")]
    Sent(&'a SentTag),
    #[displaydoc("{0}")]
    Received(&'a ReceivedTag),
    #[displaydoc("{0}")]
    LocalSigned(&'a LocalSignedTag),
    #[displaydoc("{0}")]
    RemoteSigned(&'a RemoteSignedTag),
}

impl MappingTagRef<'_> {
    pub fn to_owned(self) -> MappingTag {
        match self {
            Self::Computed(tag) => MappingTag::Computed((*tag).clone()),
            Self::Sent(tag) => MappingTag::Sent((*tag).clone()),
            Self::Received(tag) => MappingTag::Received((*tag).clone()),
            Self::LocalSigned(tag) => MappingTag::LocalSigned((*tag).clone()),
            Self::RemoteSigned(tag) => MappingTag::RemoteSigned((*tag).clone()),
        }
    }

    pub fn to_collected(self) -> CollectedTag {
        CollectedTag(self.to_owned())
    }
}

#[derive(displaydoc::Display, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnyTagRef<'a> {
    #[displaydoc("{0}")]
    Scalar(ScalarTagRef<'a>),
    #[displaydoc("{0}")]
    Mapping(MappingTagRef<'a>),
}

impl AnyTagRef<'_> {
    pub fn to_owned(self) -> AnyTag {
        match self {
            Self::Scalar(tag) => AnyTag::Scalar(tag.to_owned()),
            Self::Mapping(tag) => AnyTag::Mapping(tag.to_owned()),
        }
    }
}

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnyTag {
    #[displaydoc("{0}")]
    Scalar(ScalarTag),
    #[displaydoc("{0}")]
    Mapping(MappingTag),
}

impl AnyTag {
    #[cfg(feature = "dev")]
    pub fn as_ref(&self) -> AnyTagRef<'_> {
        match self {
            Self::Scalar(tag) => AnyTagRef::Scalar(tag.as_ref()),
            Self::Mapping(tag) => AnyTagRef::Mapping(tag.as_ref()),
        }
    }
}
