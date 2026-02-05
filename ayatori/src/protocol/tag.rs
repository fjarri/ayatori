use alloc::{format, string::String};
use core::fmt::{self, Display};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TagKind {
    Computed,
    Sent,
    Received,
    Deserialized,
    Signed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Tag {
    name: String,
    kind: TagKind,
    collected: bool,
}

impl Tag {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn short_name(&self) -> &str {
        self.name.rsplit_once("/").map(|result| result.1).unwrap_or(&self.name)
    }

    pub fn with_name(&self, name: &str) -> Self {
        Self {
            name: name.into(),
            kind: self.kind,
            collected: self.collected,
        }
    }

    pub fn computed(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Computed,
            collected: false,
        }
    }

    pub fn sent(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Sent,
            collected: false,
        }
    }

    pub fn received(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Received,
            collected: false,
        }
    }

    pub fn deserialized(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Deserialized,
            collected: false,
        }
    }

    pub fn signed(name: &str) -> Self {
        Self {
            name: name.into(),
            kind: TagKind::Signed,
            collected: false,
        }
    }

    pub fn collected(&self) -> Self {
        assert!(!self.collected);
        Self {
            name: self.name.clone(),
            kind: self.kind,
            collected: true,
        }
    }

    pub fn with_prefix(self, prefix: &str) -> Self {
        let new_name = format!("{}/{}", prefix, self.name);

        Self {
            name: new_name,
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
            TagKind::Computed => write!(f, "{}", self.name),
            TagKind::Sent => write!(f, "sent({})", self.name),
            TagKind::Received => write!(f, "received({})", self.name),
            TagKind::Deserialized => write!(f, "deserialized({})", self.name),
            TagKind::Signed => write!(f, "signed({})", self.name),
        }?;
        if self.collected {
            write!(f, ")")?;
        }
        Ok(())
    }
}
