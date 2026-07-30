use serde::{Deserialize, Serialize};

use super::{
    errors::UnionCastError,
    specific_tags::{
        CollectedTag, ComputedMappingTag, ComputedScalarTag, LocalSignedBCTag, LocalSignedDMTag, MergedScalarTag,
        ReceivedTag, RemoteSignedTag, ScalarArgumentTag, SentBCTag, SentDMTag,
    },
};

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ScalarTag {
    #[displaydoc("{0}")]
    Computed(ComputedScalarTag),
    #[displaydoc("{0}")]
    LocalSigned(LocalSignedBCTag),
    #[displaydoc("{0}")]
    Sent(SentBCTag),
    #[displaydoc("{0}")]
    Merged(MergedScalarTag),
    #[displaydoc("{0}")]
    Argument(ScalarArgumentTag),
    #[displaydoc("{0}")]
    Collected(CollectedTag),
}

impl ScalarTag {
    pub fn as_ref(&self) -> ScalarTagRef<'_> {
        match self {
            Self::Computed(tag) => ScalarTagRef::Computed(tag),
            Self::LocalSigned(tag) => ScalarTagRef::LocalSigned(tag),
            Self::Sent(tag) => ScalarTagRef::Sent(tag),
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
    Sent(SentDMTag),
    #[displaydoc("{0}")]
    Received(ReceivedTag),
    #[displaydoc("{0}")]
    LocalSigned(LocalSignedDMTag),
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
    LocalSigned(&'a LocalSignedBCTag),
    #[displaydoc("{0}")]
    Sent(&'a SentBCTag),
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
            Self::LocalSigned(tag) => ScalarTag::LocalSigned((*tag).clone()),
            Self::Sent(tag) => ScalarTag::Sent((*tag).clone()),
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
    Sent(&'a SentDMTag),
    #[displaydoc("{0}")]
    Received(&'a ReceivedTag),
    #[displaydoc("{0}")]
    LocalSigned(&'a LocalSignedDMTag),
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

    pub fn to_collected(self, disambiguator: Option<&str>) -> CollectedTag {
        CollectedTag::new(self.to_owned(), disambiguator)
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

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AnyTag {
    #[displaydoc("{0}")]
    Scalar(ScalarTag),
    #[displaydoc("{0}")]
    Mapping(MappingTag),
}

impl AnyTag {
    pub fn as_ref(&self) -> AnyTagRef<'_> {
        match self {
            Self::Scalar(tag) => AnyTagRef::Scalar(tag.as_ref()),
            Self::Mapping(tag) => AnyTagRef::Mapping(tag.as_ref()),
        }
    }
}

impl TryFrom<AnyTag> for ScalarTag {
    type Error = UnionCastError;
    fn try_from(source: AnyTag) -> Result<Self, Self::Error> {
        match source {
            AnyTag::Scalar(tag) => Ok(tag),
            AnyTag::Mapping(_) => Err(UnionCastError),
        }
    }
}

impl TryFrom<AnyTag> for MappingTag {
    type Error = UnionCastError;
    fn try_from(source: AnyTag) -> Result<Self, Self::Error> {
        match source {
            AnyTag::Scalar(_) => Err(UnionCastError),
            AnyTag::Mapping(tag) => Ok(tag),
        }
    }
}
