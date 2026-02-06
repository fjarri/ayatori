use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::{self, Display};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TagKind {
    Computed,
    Sent,
    Received,
    Deserialized,
    Signed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct FullName {
    prefix: Vec<String>,
    name: String,
}

impl FullName {
    pub fn new(name: &str) -> Self {
        Self {
            prefix: Vec::new(),
            name: name.to_string(),
        }
    }

    pub fn with_name(self, name: &str) -> Self {
        Self {
            prefix: self.prefix,
            name: name.to_string(),
        }
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Tag {
    full_name: FullName,
    kind: TagKind,
    collected: bool,
}

impl Tag {
    pub fn name(&self) -> &str {
        &self.full_name.name
    }

    pub fn full_name(&self) -> &FullName {
        &self.full_name
    }

    pub fn with_name(self, name: &str) -> Self {
        Self {
            full_name: self.full_name.with_name(name),
            kind: self.kind,
            collected: self.collected,
        }
    }

    pub fn with_added_prefix(self, prefix: &str) -> Self {
        Self {
            full_name: self.full_name.with_added_prefix(prefix),
            kind: self.kind,
            collected: self.collected,
        }
    }

    pub fn computed(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: TagKind::Computed,
            collected: false,
        }
    }

    pub fn sent(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: TagKind::Sent,
            collected: false,
        }
    }

    pub fn received(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: TagKind::Received,
            collected: false,
        }
    }

    pub fn received_with_full_name(full_name: &FullName) -> Self {
        Self {
            full_name: full_name.clone(),
            kind: TagKind::Received,
            collected: false,
        }
    }

    pub fn deserialized(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: TagKind::Deserialized,
            collected: false,
        }
    }

    pub fn signed(name: &str) -> Self {
        Self {
            full_name: FullName::new(name),
            kind: TagKind::Signed,
            collected: false,
        }
    }

    pub fn collected(&self) -> Self {
        assert!(!self.collected);
        Self {
            full_name: self.full_name.clone(),
            kind: self.kind,
            collected: true,
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
            TagKind::Deserialized => write!(f, "deserialized({})", self.full_name),
            TagKind::Signed => write!(f, "signed({})", self.full_name),
        }?;
        if self.collected {
            write!(f, ")")?;
        }
        Ok(())
    }
}
