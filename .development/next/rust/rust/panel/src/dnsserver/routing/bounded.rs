use serde::{de, Deserialize, Deserializer, Serialize};
use std::{fmt, marker::PhantomData};

#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct Bounded<T, const N: usize>(pub(super) Vec<T>);

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Sequence<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> de::Visitor<'de> for Sequence<T, MAX> {
            type Value = Bounded<T, MAX>;

            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(out, "a sequence of at most {MAX} values")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut items: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(item) = items.next_element()? {
                    if values.len() == MAX {
                        return Err(de::Error::invalid_length(MAX + 1, &self));
                    }
                    values.push(item);
                }
                Ok(Bounded(values))
            }
        }
        de.deserialize_seq(Sequence(PhantomData))
    }
}
