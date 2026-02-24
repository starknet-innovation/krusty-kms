//! Multicall calldata encoding for `__execute__`.

use starknet_rust::core::types::{Call, Felt};

/// Encode a list of `Call`s into the `__execute__` multicall format.
///
/// Layout: `[num_calls, to_0, selector_0, data_0_len, data_0..., to_1, ...]`
pub fn encode_execute_calldata(calls: &[Call]) -> Vec<Felt> {
    let mut calldata = vec![Felt::from(calls.len() as u64)];
    for call in calls {
        calldata.push(call.to);
        calldata.push(call.selector);
        calldata.push(Felt::from(call.calldata.len() as u64));
        calldata.extend_from_slice(&call.calldata);
    }
    calldata
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty_calls() {
        let calldata = encode_execute_calldata(&[]);
        assert_eq!(calldata, vec![Felt::ZERO]); // num_calls = 0
    }

    #[test]
    fn test_encode_single_call() {
        let call = Call {
            to: Felt::from(0x111u64),
            selector: Felt::from(0x222u64),
            calldata: vec![Felt::from(0x333u64), Felt::from(0x444u64)],
        };
        let encoded = encode_execute_calldata(&[call]);

        assert_eq!(encoded.len(), 6); // 1 + (1+1+1+2)
        assert_eq!(encoded[0], Felt::from(1u64)); // num_calls
        assert_eq!(encoded[1], Felt::from(0x111u64)); // to
        assert_eq!(encoded[2], Felt::from(0x222u64)); // selector
        assert_eq!(encoded[3], Felt::from(2u64)); // data_len
        assert_eq!(encoded[4], Felt::from(0x333u64)); // data[0]
        assert_eq!(encoded[5], Felt::from(0x444u64)); // data[1]
    }

    #[test]
    fn test_encode_multiple_calls() {
        let call1 = Call {
            to: Felt::from(0x1u64),
            selector: Felt::from(0x2u64),
            calldata: vec![Felt::from(0x3u64)],
        };
        let call2 = Call {
            to: Felt::from(0x4u64),
            selector: Felt::from(0x5u64),
            calldata: vec![],
        };
        let encoded = encode_execute_calldata(&[call1, call2]);

        assert_eq!(encoded.len(), 8); // 1 + (1+1+1+1) + (1+1+1+0)
        assert_eq!(encoded[0], Felt::from(2u64)); // num_calls
        // Call 1
        assert_eq!(encoded[1], Felt::from(0x1u64));
        assert_eq!(encoded[2], Felt::from(0x2u64));
        assert_eq!(encoded[3], Felt::from(1u64)); // data_len
        assert_eq!(encoded[4], Felt::from(0x3u64));
        // Call 2
        assert_eq!(encoded[5], Felt::from(0x4u64));
        assert_eq!(encoded[6], Felt::from(0x5u64));
        assert_eq!(encoded[7], Felt::ZERO); // data_len = 0
    }

    #[test]
    fn test_encode_call_no_data() {
        let call = Call {
            to: Felt::from(0xABCu64),
            selector: Felt::from(0xDEFu64),
            calldata: vec![],
        };
        let encoded = encode_execute_calldata(&[call]);

        assert_eq!(encoded.len(), 4); // 1 + (1+1+1)
        assert_eq!(encoded[3], Felt::ZERO); // data_len = 0
    }
}
