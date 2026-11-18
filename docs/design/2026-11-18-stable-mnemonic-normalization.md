# Stable mnemonic normalization

Krusty normalizes BIP-39 passphrases with NFKD before deriving a seed. Unicode
can assign combining classes to previously unassigned characters, changing
normalization for passphrases accepted by earlier versions of Krusty.

Keep `unicode-normalization` at 0.1.25 in the workspace lockfile to retain
the Unicode 17 tables used for Krusty's locked builds. The published
`krusty-kms` manifest allows 0.1.26. That release was available before
Krusty 3.1.0, so Rust applications can already have derived seeds with
Unicode 18 depending on their own lockfile. An exact manifest pin to
0.1.25 would change those derivations.

A regression vector covers a passphrase whose combining marks reorder under
Unicode 18. Any future table upgrade that changes an existing seed requires
versioned derivation and a recovery path for existing wallets.
