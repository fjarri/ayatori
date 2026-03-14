use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use serde::{Deserialize, Serialize};

use crate::error::LocalError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum TagKind {
    /// A locally computed value coming from an explicit computation/verification node
    /// (not from serialization/deserialization).
    /// The name of the tag will come from what the user provided when creating the node.
    /// The contents are of some user type.
    Computed,
    /// A marker indicating that a value was sent out.
    /// The name of the tag will come from the protocol message name.
    /// The contents of the value are `()`.
    Sent,
    /// A signed value + metadata originating from another node.
    /// The name of the tag will come from the protocol message name.
    /// The contents are `SignedValue`.
    SignedRemote,
    /// A signed value + metadata originating from this node.
    /// The name of the tag will come from the protocol message name.
    /// The contents are `SignedValue`.
    SignedLocal,
    /// A value deserialized from a message received from another node.
    /// The name of the tag will come from the protocol message name.
    /// The contents are of some user type.
    Received,
}

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
        for prefix in self.prefix.iter() {
            write!(f, "{}/", prefix)?;
        }
        write!(f, "{}", self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Tag {
    full_name: FullName,
    kind: TagKind,
    collected: bool,
}

impl Tag {
    pub fn full_name(&self) -> &FullName {
        &self.full_name
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self {
            full_name: self.full_name.with_added_prefix(prefix),
            kind: self.kind,
            collected: self.collected,
        }
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if self.collected {
            write!(f, "collected(")?;
        }
        match self.kind {
            TagKind::Computed => write!(f, "{}", self.full_name),
            TagKind::Sent => write!(f, "sent({})", self.full_name),
            TagKind::Received => write!(f, "received({})", self.full_name),
            TagKind::SignedLocal => write!(f, "signed-local({})", self.full_name),
            TagKind::SignedRemote => write!(f, "signed-remote({})", self.full_name),
        }?;
        if self.collected {
            write!(f, ")")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ScalarTag(Tag);

impl ScalarTag {
    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }

    pub fn computed(name: &str) -> Self {
        Self(Tag {
            full_name: FullName::new(name),
            kind: TagKind::Computed,
            collected: false,
        })
    }
}

impl AsRef<Tag> for ScalarTag {
    fn as_ref(&self) -> &Tag {
        &self.0
    }
}

impl Display for ScalarTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ArrayTag(Tag);

impl ArrayTag {
    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self(self.0.with_added_prefix(prefix))
    }

    pub fn computed(name: &str) -> Self {
        Self(Tag {
            full_name: FullName::new(name),
            kind: TagKind::Computed,
            collected: false,
        })
    }

    pub fn signed_remote(name: &str) -> Self {
        Self(Tag {
            full_name: FullName::new(name),
            kind: TagKind::SignedRemote,
            collected: false,
        })
    }

    pub fn signed_local(name: &str) -> Self {
        Self(Tag {
            full_name: FullName::new(name),
            kind: TagKind::SignedLocal,
            collected: false,
        })
    }

    pub fn to_sent(&self) -> Result<Self, LocalError> {
        if self.0.kind != TagKind::SignedLocal {
            return Err(LocalError::new("Only SignedLocal tags can be converted to Sent"));
        }
        Ok(Self(Tag {
            full_name: self.0.full_name.clone(),
            kind: TagKind::Sent,
            collected: false,
        }))
    }

    pub fn signed_remote_with_full_name(full_name: &FullName) -> Self {
        Self(Tag {
            full_name: full_name.clone(),
            kind: TagKind::SignedRemote,
            collected: false,
        })
    }

    pub fn to_received(&self) -> Result<Self, LocalError> {
        if self.0.kind != TagKind::SignedRemote {
            return Err(LocalError::new("Only SignedRemote tags can be converted to Received"));
        }
        Ok(Self(Tag {
            full_name: self.0.full_name.clone(),
            kind: TagKind::Received,
            collected: false,
        }))
    }

    pub fn collected(&self) -> ScalarTag {
        assert!(!self.0.collected); // TODO: is this necessary?
        ScalarTag(Tag {
            full_name: self.0.full_name.clone(),
            kind: self.0.kind,
            collected: true,
        })
    }
}

impl AsRef<Tag> for ArrayTag {
    fn as_ref(&self) -> &Tag {
        &self.0
    }
}

impl Display for ArrayTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AnyTagRef<'a> {
    Scalar(&'a ScalarTag),
    Array(&'a ArrayTag),
}

impl<'a> AnyTagRef<'a> {
    pub fn scalar(&self) -> Option<&ScalarTag> {
        match self {
            Self::Scalar(tag) => Some(tag),
            Self::Array(_) => None,
        }
    }

    pub fn array(&self) -> Option<&ArrayTag> {
        match self {
            Self::Scalar(_) => None,
            Self::Array(tag) => Some(tag),
        }
    }

    pub fn to_owned(&self) -> AnyTag {
        match self {
            Self::Scalar(tag) => AnyTag::Scalar((*tag).clone()),
            Self::Array(tag) => AnyTag::Array((*tag).clone()),
        }
    }
}

impl<'a> Display for AnyTagRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Scalar(tag) => write!(f, "{tag}"),
            Self::Array(tag) => write!(f, "{tag}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AnyTag {
    Scalar(ScalarTag),
    Array(ArrayTag),
}
