//! Exact JavaScript integer parsing before wasm-bindgen can narrow a value.

use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

fn exact<T: DeserializeOwned>(value: JsValue, label: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|_| {
        JsValue::from_str(&format!(
            "Invalid {label}: expected an exact integer in range"
        ))
    })
}

pub(crate) fn u8(value: JsValue, label: &str) -> Result<u8, JsValue> {
    exact(value, label)
}

pub(crate) fn u32(value: JsValue, label: &str) -> Result<u32, JsValue> {
    exact(value, label)
}

pub(crate) fn u64(value: JsValue, label: &str) -> Result<u64, JsValue> {
    exact(value, label)
}

pub(crate) fn derivation_indices(
    address_index: JsValue,
    account_index: JsValue,
) -> Result<(u32, u32), JsValue> {
    Ok((
        u32(address_index, "address index")?,
        u32(account_index, "account index")?,
    ))
}

pub(crate) fn optional_u8(value: JsValue, label: &str) -> Result<Option<u8>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        u8(value, label).map(Some)
    }
}

pub(crate) fn optional_u32(value: JsValue, label: &str) -> Result<Option<u32>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        u32(value, label).map(Some)
    }
}

pub(crate) fn optional_u64(value: JsValue, label: &str) -> Result<Option<u64>, JsValue> {
    if value.is_null() || value.is_undefined() {
        Ok(None)
    } else {
        u64(value, label).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn rejects_wrapped_and_fractional_numbers() {
        for value in [256.0, -1.0, 1.5, f64::NAN] {
            assert!(u8(JsValue::from_f64(value), "byte").is_err());
        }
        assert_eq!(u8(JsValue::from_f64(255.0), "byte").unwrap(), 255);
        assert!(u32(JsValue::from_f64(4_294_967_296.0), "index").is_err());
        assert_eq!(
            u32(JsValue::from_f64(4_294_967_295.0), "index").unwrap(),
            u32::MAX
        );
    }

    #[wasm_bindgen_test]
    fn rejects_out_of_range_nonce_bigint() {
        let max = js_sys::BigInt::new(&JsValue::from_str("18446744073709551615")).unwrap();
        let overflow = js_sys::BigInt::new(&JsValue::from_str("18446744073709551616")).unwrap();
        let unsafe_number = JsValue::from_f64(9_007_199_254_740_992.0);
        let safe_bigint = js_sys::BigInt::new(&JsValue::from_str("9007199254740992")).unwrap();
        assert_eq!(u64(max.into(), "nonce").unwrap(), u64::MAX);
        assert!(u64(overflow.into(), "nonce").is_err());
        assert!(u64(unsafe_number, "nonce").is_err());
        assert_eq!(u64(safe_bigint.into(), "nonce").unwrap(), 1u64 << 53);
    }
}
