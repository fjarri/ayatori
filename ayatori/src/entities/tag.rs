use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use serde::{Deserialize, Serialize};

use crate::errors::LocalError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ScalarTagKind {
    /// A locally computed value coming from an explicit computation/verification node
    /// (not from serialization/deserialization).
    /// The name of the tag will come from what the user provided when creating the node.
    /// The contents are of some user type.
    Computed,
    Collected(ArrayTagKind),
}

impl Display for ScalarTagKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Computed => write!(f, ""),
            Self::Collected(kind) => {
                write!(f, "collected")?;
                if !matches!(kind, ArrayTagKind::Computed) {
                    write!(f, "-{kind}")
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ArrayTagKind {
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

impl Display for ArrayTagKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Computed => write!(f, ""),
            Self::Sent => write!(f, "sent"),
            Self::Received => write!(f, "received"),
            Self::SignedLocal => write!(f, "signed-local"),
            Self::SignedRemote => write!(f, "signed-remote"),
        }
    }
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
pub(crate) struct ScalarTag {
    full_name: FullName,
    kind: ScalarTagKind,
}

impl ScalarTag {
    pub fn full_name(&self) -> &FullName {
        &self.full_name
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self {
            full_name: self.full_name.with_added_prefix(prefix),
            kind: self.kind,
        }
    }

    pub fn computed(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: ScalarTagKind::Computed,
        }
    }
}

impl Display for ScalarTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self.kind {
            ScalarTagKind::Computed => write!(f, "{}", self.full_name),
            _ => write!(f, "{}({})", self.kind, self.full_name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ArrayTag {
    full_name: FullName,
    kind: ArrayTagKind,
}

impl ArrayTag {
    pub fn full_name(&self) -> &FullName {
        &self.full_name
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self {
            full_name: self.full_name.with_added_prefix(prefix),
            kind: self.kind,
        }
    }

    pub fn computed(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: ArrayTagKind::Computed,
        }
    }

    pub fn signed_remote(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: ArrayTagKind::SignedRemote,
        }
    }

    pub fn signed_local(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: ArrayTagKind::SignedLocal,
        }
    }

    pub fn to_sent(&self) -> Result<Self, LocalError> {
        if self.kind != ArrayTagKind::SignedLocal {
            return Err(LocalError::new("Only SignedLocal tags can be converted to Sent"));
        }
        Ok(Self {
            full_name: self.full_name.clone(),
            kind: ArrayTagKind::Sent,
        })
    }

    pub fn signed_remote_with_full_name(full_name: &FullName) -> Self {
        Self {
            full_name: full_name.clone(),
            kind: ArrayTagKind::SignedRemote,
        }
    }

    pub fn to_received(&self) -> Result<Self, LocalError> {
        if self.kind != ArrayTagKind::SignedRemote {
            return Err(LocalError::new("Only SignedRemote tags can be converted to Received"));
        }
        Ok(Self {
            full_name: self.full_name.clone(),
            kind: ArrayTagKind::Received,
        })
    }

    pub fn collected(&self) -> ScalarTag {
        ScalarTag {
            full_name: self.full_name.clone(),
            kind: ScalarTagKind::Collected(self.kind),
        }
    }
}

impl Display for ArrayTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self.kind {
            ArrayTagKind::Computed => write!(f, "{}", self.full_name),
            _ => write!(f, "{}({})", self.kind, self.full_name),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AnyTagRef<'a> {
    Scalar(&'a ScalarTag),
    Array(&'a ArrayTag),
}

impl<'a> AnyTagRef<'a> {
    pub fn scalar(&self) -> Option<&'a ScalarTag> {
        match self {
            Self::Scalar(tag) => Some(tag),
            Self::Array(_) => None,
        }
    }

    pub fn array(&self) -> Option<&'a ArrayTag> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnyTag {
    Scalar(ScalarTag),
    Array(ArrayTag),
}

impl Display for AnyTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Scalar(tag) => write!(f, "{tag}"),
            Self::Array(tag) => write!(f, "{tag}"),
        }
    }
}
