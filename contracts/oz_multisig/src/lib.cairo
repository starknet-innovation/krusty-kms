// Source-equivalent wrapper for the upstream OpenZeppelin multisig component.
//
// OpenZeppelin ships the multisig as a governance component rather than a
// declareable preset. This wrapper exposes a concrete contract class while
// keeping the upstream constructor and external IMultisig surface unchanged.
#[starknet::contract]
pub mod MultisigWallet {
    use openzeppelin_governance::multisig::MultisigComponent;
    use starknet::ContractAddress;

    component!(path: MultisigComponent, storage: multisig, event: MultisigEvent);

    #[abi(embed_v0)]
    pub(crate) impl MultisigImpl = MultisigComponent::MultisigImpl<ContractState>;
    impl MultisigInternalImpl = MultisigComponent::InternalImpl<ContractState>;

    #[storage]
    pub struct Storage {
        #[substorage(v0)]
        pub multisig: MultisigComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        MultisigEvent: MultisigComponent::Event,
    }

    #[constructor]
    pub fn constructor(ref self: ContractState, quorum: u32, signers: Span<ContractAddress>) {
        self.multisig.initializer(quorum, signers);
    }
}
