use super::{AuthError, AuthResult, FieldArray, FieldValue};
use std::cmp::Ordering;

impl FieldArray {
    pub(crate) fn concat(&self, arguments: &[FieldValue]) -> AuthResult<Self> {
        let output = Self::new();
        let mut length = 0;
        for value in
            std::iter::once(FieldValue::from(self.clone())).chain(arguments.iter().cloned())
        {
            match value {
                FieldValue::Array(array) => {
                    let count = array.len()?;
                    for index in 0..count {
                        if let Some(value) = array.get(index)? {
                            output.set(length + index, value)?;
                        }
                    }
                    length += count;
                }
                value => {
                    output.set(length, value)?;
                    length += 1;
                }
            }
        }
        let _ = u32::try_from(length)
            .map_err(|_| AuthError::RangeError("Invalid array length".into()))?;
        output.set_length(length)?;
        Ok(output)
    }

    pub(crate) fn sort_by(
        &self,
        compare: impl Fn(&FieldValue, &FieldValue) -> AuthResult<Ordering>,
    ) -> AuthResult<()> {
        let length = self.len()?;
        let mut values = Vec::new();
        let mut undefined = 0;
        for index in 0..length {
            if let Some(value) = self.get(index)? {
                if value.is_undefined() {
                    undefined += 1;
                } else {
                    values.push(value);
                }
            }
        }
        // Comparison failures leave indexed writes untouched; callback mutations remain observable.
        crate::memory_sort::sort_by(&mut values, compare)?;
        let count = values.len() + undefined;
        for (index, value) in values
            .into_iter()
            .chain(std::iter::repeat_n(FieldValue::Undefined, undefined))
            .enumerate()
        {
            self.set(index, value)?;
        }
        for index in count..length {
            self.delete(index)?;
        }
        Ok(())
    }
}
