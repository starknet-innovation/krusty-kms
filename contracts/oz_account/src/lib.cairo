// Source-equivalent wrapper for the upstream OpenZeppelin preset.
//
// Scarb does not emit declareable artifacts for dependency contracts from a
// bare re-export, so we keep the exact preset logic here while pinning the
// upstream preset package version in `Scarb.toml`.
#[starknet::contract(account)]
pub mod AccountUpgradeable {
    use openzeppelin_account::AccountComponent;
    use openzeppelin_account::extensions::SRC9Component;
    use openzeppelin_interfaces::upgrades::IUpgradeable;
    use openzeppelin_introspection::src5::SRC5Component;
    use openzeppelin_upgrades::UpgradeableComponent;
    use starknet::ClassHash;

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: SRC9Component, storage: src9, event: SRC9Event);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    #[abi(embed_v0)]
    pub(crate) impl AccountMixinImpl = AccountComponent::AccountMixinImpl<ContractState>;
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl OutsideExecutionV2Impl = SRC9Component::OutsideExecutionV2Impl<ContractState>;
    impl OutsideExecutionInternalImpl = SRC9Component::InternalImpl<ContractState>;

    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    pub struct Storage {
        #[substorage(v0)]
        pub account: AccountComponent::Storage,
        #[substorage(v0)]
        pub src5: SRC5Component::Storage,
        #[substorage(v0)]
        pub src9: SRC9Component::Storage,
        #[substorage(v0)]
        pub upgradeable: UpgradeableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        SRC9Event: SRC9Component::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[constructor]
    pub fn constructor(ref self: ContractState, public_key: felt252) {
        self.account.initializer(public_key);
        self.src9.initializer();
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.account.assert_only_self();
            self.upgradeable.upgrade(new_class_hash);
        }
    }
}
