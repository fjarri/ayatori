use serde::{Deserialize, Serialize};

use super::{
    errors::UnionCastError,
    specific_tags::{
        CollectedTag, ComputedMappingTag, ComputedScalarTag, LocalSignedBCTag, LocalSignedDMTag, MergedScalarTag,
        ReceivedTag, RemoteSignedTag, ScalarArgumentTag, SentBCTag, SentDMTag,
    },
};

macro_rules! define_tag_union {
    (
        $union_name:ident
        $union_ref_name:ident
        {
            $($variant:ident($tag_type:ident)),+ $(,)?
        }
        $($with_added_prefix:ident)?
    ) => {
        #[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        pub(crate) enum $union_name {
            $(
                #[displaydoc("{0}")]
                $variant($tag_type),
            )+
        }

        impl $union_name {
            pub fn as_ref(&self) -> $union_ref_name<'_> {
                match self {
                    $(Self::$variant(tag) => $union_ref_name::$variant(tag),)+
                }
            }
        }

        define_tag_union!(@maybe_with_added_prefix $union_name $($variant),+ $($with_added_prefix)?);

        #[derive(displaydoc::Display, Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum $union_ref_name<'a> {
            $(
                #[displaydoc("{0}")]
                $variant(&'a $tag_type),
            )+
        }

        impl $union_ref_name<'_> {
            pub fn to_owned(self) -> $union_name {
                match self {
                    $(Self::$variant(tag) => $union_name::$variant((*tag).clone()),)+
                }
            }
        }
    };

    (@maybe_with_added_prefix $union_name:ident $($variant:ident),+ with_added_prefix) => {
        impl $union_name {
            pub fn with_added_prefix(self, prefix: &str) -> Self {
                match self {
                    $(Self::$variant(tag) => Self::$variant(tag.with_added_prefix(prefix)),)+
                }
            }
        }
    };

    (@maybe_with_added_prefix $union_name:ident $($variant:ident),+) => {};
}

define_tag_union!(
    ScalarTag
    ScalarTagRef
    {
        Computed(ComputedScalarTag),
        LocalSigned(LocalSignedBCTag),
        Sent(SentBCTag),
        Merged(MergedScalarTag),
        Argument(ScalarArgumentTag),
        Collected(CollectedTag),
    }
);

define_tag_union!(
    MappingTag
    MappingTagRef
    {
        Computed(ComputedMappingTag),
        Sent(SentDMTag),
        Received(ReceivedTag),
        LocalSigned(LocalSignedDMTag),
        RemoteSigned(RemoteSignedTag),
    }
    with_added_prefix
);

impl MappingTagRef<'_> {
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
