use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;

struct MockProvider {
    responses: Mutex<VecDeque<Vec<StarknetRsFelt>>>,
    requests: Mutex<Vec<FunctionCall>>,
}

impl MockProvider {
    fn with_responses(responses: Vec<Vec<StarknetRsFelt>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl TongoProvider for MockProvider {
    async fn call(
        &self,
        request: FunctionCall,
        _block_id: BlockId,
    ) -> std::result::Result<Vec<StarknetRsFelt>, starknet_rust::providers::ProviderError> {
        self.requests.lock().unwrap().push(request);
        Ok(self.responses.lock().unwrap().pop_front().unwrap())
    }
}

#[tokio::test]
async fn mocked_provider_builds_the_rate_adapter_call() {
    let provider = Arc::new(MockProvider::with_responses(vec![vec![
        StarknetRsFelt::from(42u64),
    ]]));
    let contract = TongoContract::with_provider(provider.clone(), CoreFelt::from(9u64));

    assert_eq!(contract.get_rate().await.unwrap(), 42);
    let calls = provider.requests.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].entry_point_selector,
        get_selector_from_name("get_rate").unwrap()
    );
    assert!(calls[0].calldata.is_empty());
}

#[tokio::test]
async fn mocked_provider_decodes_the_range_bit_size() {
    let provider = Arc::new(MockProvider::with_responses(vec![vec![
        StarknetRsFelt::from(40u64),
    ]]));
    let contract = TongoContract::with_provider(provider.clone(), CoreFelt::from(9u64));

    assert_eq!(contract.get_bit_size().await.unwrap(), 40);
    let calls = provider.requests.lock().unwrap();
    assert_eq!(
        calls[0].entry_point_selector,
        get_selector_from_name("get_bit_size").unwrap()
    );
    assert!(calls[0].calldata.is_empty());
}

#[tokio::test]
async fn mocked_provider_decodes_the_erc20_address() {
    let provider = Arc::new(MockProvider::with_responses(vec![vec![
        StarknetRsFelt::from(0x1234u64),
    ]]));
    let contract = TongoContract::with_provider(provider.clone(), CoreFelt::from(9u64));

    assert_eq!(
        contract.get_erc20().await.unwrap(),
        CoreFelt::from(0x1234u64)
    );
    let calls = provider.requests.lock().unwrap();
    assert_eq!(
        calls[0].entry_point_selector,
        get_selector_from_name("ERC20").unwrap()
    );
    assert!(calls[0].calldata.is_empty());
}

#[tokio::test]
async fn mocked_provider_adapts_audit_none() {
    let provider = Arc::new(MockProvider::with_responses(vec![vec![
        StarknetRsFelt::ONE,
    ]]));
    let contract = TongoContract::with_provider(provider.clone(), CoreFelt::from(9u64));
    let key = krusty_kms_crypto::StarkCurve::generator();

    assert!(contract.get_audit(&key).await.unwrap().is_none());
    let calls = provider.requests.lock().unwrap();
    assert_eq!(
        calls[0].entry_point_selector,
        get_selector_from_name("get_audit").unwrap()
    );
    assert_eq!(calls[0].calldata.len(), 2);
}

#[tokio::test]
async fn mocked_provider_decodes_account_state() {
    let key = krusty_kms_crypto::StarkCurve::generator();
    let affine = key.to_affine().unwrap();
    let x = core_felt_to_rs(affine.x());
    let y = core_felt_to_rs(affine.y());
    let provider = Arc::new(MockProvider::with_responses(vec![vec![
        x,
        y,
        x,
        y,
        x,
        y,
        x,
        y,
        StarknetRsFelt::from(3u64),
    ]]));
    let contract = TongoContract::with_provider(provider.clone(), CoreFelt::from(9u64));

    let state = contract.get_state(&key).await.unwrap();
    assert_eq!(state.nonce, CoreFelt::from(3u64));
    assert_eq!(state.balance.l, key);
    assert_eq!(state.pending.r, key);
    let calls = provider.requests.lock().unwrap();
    assert_eq!(
        calls[0].entry_point_selector,
        get_selector_from_name("get_state").unwrap()
    );
    assert_eq!(calls[0].calldata, vec![x, y]);
}

/// Oversized RPC felts must error instead of silently truncating (M-13):
/// a truncated `rate` feeds `approve(amount * rate)`.
#[test]
fn felt_conversions_reject_truncation() {
    assert_eq!(
        felt_to_u128_checked(&StarknetRsFelt::from(42u64), "test").unwrap(),
        42
    );
    assert_eq!(
        felt_to_u128_checked(&StarknetRsFelt::from(u128::MAX), "test").unwrap(),
        u128::MAX
    );
    let over_u128 = StarknetRsFelt::from(u128::MAX) + StarknetRsFelt::ONE;
    assert!(felt_to_u128_checked(&over_u128, "test").is_err());

    assert_eq!(
        felt_to_u32_checked(&StarknetRsFelt::from(u32::MAX), "test").unwrap(),
        u32::MAX
    );
    let over_u32 = StarknetRsFelt::from(u64::from(u32::MAX) + 1);
    assert!(felt_to_u32_checked(&over_u32, "test").is_err());
}
