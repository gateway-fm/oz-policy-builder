# Target execution test fixture

`test_contract_data.wasm` is the 824-byte fixture from `soroban-sdk` version
`26.1.0`, path `test_wasms/test_contract_data.wasm`, published by Stellar under
Apache-2.0. Its SHA-256 is
`fd41d2f77920ca07b723e05f732a82db4c2f6459eb2be6b40c4f225434569550`.

The fixture exports `put`, `get`, and `del`. The selected-key snapshot test
invokes `get` against captured instance, code, and one storage entry, and
checks that `get` of an uncaptured key fails. It also invokes `put`: a write to
an uncaptured key is refused, and a write to the captured key commits and is
read back from a later disposable ledger. It tests the reconstructed execution
mechanism; it does not represent a deployed application, complete target
state, or policy authorization.
