# Changelog

## [Unreleased](https://github.com/babylonchain/babylon-contract/tree/HEAD)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.6.0...HEAD)

## [v0.6.0](https://github.com/babylonchain/babylon-contract/tree/v0.6.0) (2024-06-07)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.5.3...v0.6.0)

**Closed issues:**

- crypto: implement EOTS using `k256` [\#134](https://github.com/babylonchain/babylon-contract/issues/134)
- fix contract size [\#126](https://github.com/babylonchain/babylon-contract/issues/126)
- replace `Vec<u8>` with `Binary` for exec messages [\#125](https://github.com/babylonchain/babylon-contract/issues/125)
- Finality signatures verification [\#117](https://github.com/babylonchain/babylon-contract/issues/117)
- Benchmarking ci job failing [\#112](https://github.com/babylonchain/babylon-contract/issues/112)
- admin commands for contracts [\#107](https://github.com/babylonchain/babylon-contract/issues/107)
- Voting table [\#103](https://github.com/babylonchain/babylon-contract/issues/103)
- Implement BTC undelegation [\#99](https://github.com/babylonchain/babylon-contract/issues/99)
- crypto: EOTS in rust [\#93](https://github.com/babylonchain/babylon-contract/issues/93)
- Add `validate` methods [\#83](https://github.com/babylonchain/babylon-contract/issues/83)

**Merged pull requests:**

- crypto: use k256 instead of secp256kfun for implementing EOTS [\#136](https://github.com/babylonchain/babylon-contract/pull/136) ([SebastianElvis](https://github.com/SebastianElvis))
- F/finality sig verification [\#128](https://github.com/babylonchain/babylon-contract/pull/128) ([maurolacy](https://github.com/maurolacy))
- chore: fix size of BTC staking contract [\#127](https://github.com/babylonchain/babylon-contract/pull/127) ([SebastianElvis](https://github.com/SebastianElvis))
- F/merkle rs [\#124](https://github.com/babylonchain/babylon-contract/pull/124) ([maurolacy](https://github.com/maurolacy))
- finality: vanilla sudo message [\#123](https://github.com/babylonchain/babylon-contract/pull/123) ([SebastianElvis](https://github.com/SebastianElvis))
- F/public randomness [\#122](https://github.com/babylonchain/babylon-contract/pull/122) ([maurolacy](https://github.com/maurolacy))
- chore: fixing inconsistency of protobuf objects [\#121](https://github.com/babylonchain/babylon-contract/pull/121) ([SebastianElvis](https://github.com/SebastianElvis))
- F/voting table height 2 [\#119](https://github.com/babylonchain/babylon-contract/pull/119) ([maurolacy](https://github.com/maurolacy))
- F/ibc proto improvements [\#116](https://github.com/babylonchain/babylon-contract/pull/116) ([maurolacy](https://github.com/maurolacy))
- C/babylon update sync [\#115](https://github.com/babylonchain/babylon-contract/pull/115) ([maurolacy](https://github.com/maurolacy))
- F/submit finality sigs [\#114](https://github.com/babylonchain/babylon-contract/pull/114) ([maurolacy](https://github.com/maurolacy))
- F/voting table height [\#113](https://github.com/babylonchain/babylon-contract/pull/113) ([maurolacy](https://github.com/maurolacy))
- Fix/main ci 2 [\#111](https://github.com/babylonchain/babylon-contract/pull/111) ([maurolacy](https://github.com/maurolacy))
- Update schemas [\#110](https://github.com/babylonchain/babylon-contract/pull/110) ([maurolacy](https://github.com/maurolacy))
- feat: Add admin commands [\#108](https://github.com/babylonchain/babylon-contract/pull/108) ([gusin13](https://github.com/gusin13))
- F/voting table [\#106](https://github.com/babylonchain/babylon-contract/pull/106) ([maurolacy](https://github.com/maurolacy))
- F/config params [\#105](https://github.com/babylonchain/babylon-contract/pull/105) ([maurolacy](https://github.com/maurolacy))
- F/begin block handler [\#104](https://github.com/babylonchain/babylon-contract/pull/104) ([maurolacy](https://github.com/maurolacy))
- F/active delegations queries [\#102](https://github.com/babylonchain/babylon-contract/pull/102) ([maurolacy](https://github.com/maurolacy))
- F/validate methods [\#101](https://github.com/babylonchain/babylon-contract/pull/101) ([maurolacy](https://github.com/maurolacy))
- BTC undelegate basic impl [\#98](https://github.com/babylonchain/babylon-contract/pull/98) ([maurolacy](https://github.com/maurolacy))
- crypto: EOTS implementation [\#95](https://github.com/babylonchain/babylon-contract/pull/95) ([SebastianElvis](https://github.com/SebastianElvis))

## [v0.5.3](https://github.com/babylonchain/babylon-contract/tree/v0.5.3) (2024-05-13)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.5.2...v0.5.3)

**Closed issues:**

- Staking Tx Hash mismatch causing issues in `finality_provider` and `delegations_by_f_p` queries [\#94](https://github.com/babylonchain/babylon-contract/issues/94)

**Merged pull requests:**

- Fix/reverse hash [\#96](https://github.com/babylonchain/babylon-contract/pull/96) ([maurolacy](https://github.com/maurolacy))

## [v0.5.2](https://github.com/babylonchain/babylon-contract/tree/v0.5.2) (2024-05-07)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.5.1...v0.5.2)

**Merged pull requests:**

- Fix/protos [\#91](https://github.com/babylonchain/babylon-contract/pull/91) ([maurolacy](https://github.com/maurolacy))
- Fix: publish schemas on release [\#90](https://github.com/babylonchain/babylon-contract/pull/90) ([maurolacy](https://github.com/maurolacy))

## [v0.5.1](https://github.com/babylonchain/babylon-contract/tree/v0.5.1) (2024-05-06)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.5.0...v0.5.1)

**Closed issues:**

- test: formalise datagen library [\#76](https://github.com/babylonchain/babylon-contract/issues/76)

**Merged pull requests:**

- Fix/query responses [\#88](https://github.com/babylonchain/babylon-contract/pull/88) ([maurolacy](https://github.com/maurolacy))
- Release 0.5 follow up [\#87](https://github.com/babylonchain/babylon-contract/pull/87) ([maurolacy](https://github.com/maurolacy))
- datagen: refactor datagen and test utilities [\#86](https://github.com/babylonchain/babylon-contract/pull/86) ([SebastianElvis](https://github.com/SebastianElvis))

## [v0.5.0](https://github.com/babylonchain/babylon-contract/tree/v0.5.0) (2024-05-03)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.4.0...v0.5.0)

**Closed issues:**

- btcstaking: verification of {Schnorr, adaptor} signatures in BTC staking library [\#77](https://github.com/babylonchain/babylon-contract/issues/77)
- compiling IBC packets from protobuf to Rust [\#69](https://github.com/babylonchain/babylon-contract/issues/69)
- btcstaking: BTC staking library [\#64](https://github.com/babylonchain/babylon-contract/issues/64)

**Merged pull requests:**

- F/staking validation [\#82](https://github.com/babylonchain/babylon-contract/pull/82) ([maurolacy](https://github.com/maurolacy))
- F/staking queries [\#81](https://github.com/babylonchain/babylon-contract/pull/81) ([maurolacy](https://github.com/maurolacy))
- Support Mac's ugly non-standard sed [\#80](https://github.com/babylonchain/babylon-contract/pull/80) ([maurolacy](https://github.com/maurolacy))
- multi-tests follow-up [\#79](https://github.com/babylonchain/babylon-contract/pull/79) ([maurolacy](https://github.com/maurolacy))
- btcstaking: verify Schnorr/adaptor sig over txs [\#78](https://github.com/babylonchain/babylon-contract/pull/78) ([SebastianElvis](https://github.com/SebastianElvis))
- Add multi-test support [\#75](https://github.com/babylonchain/babylon-contract/pull/75) ([maurolacy](https://github.com/maurolacy))
- Update proto / apis defs [\#74](https://github.com/babylonchain/babylon-contract/pull/74) ([maurolacy](https://github.com/maurolacy))
- F/staking handling [\#73](https://github.com/babylonchain/babylon-contract/pull/73) ([maurolacy](https://github.com/maurolacy))
- BTC staking msgs [\#68](https://github.com/babylonchain/babylon-contract/pull/68) ([maurolacy](https://github.com/maurolacy))
- Fix/btc lc datagen [\#67](https://github.com/babylonchain/babylon-contract/pull/67) ([maurolacy](https://github.com/maurolacy))
- btcstaking: btcstaking library in Rust [\#65](https://github.com/babylonchain/babylon-contract/pull/65) ([SebastianElvis](https://github.com/SebastianElvis))
- BTC staking contract [\#63](https://github.com/babylonchain/babylon-contract/pull/63) ([maurolacy](https://github.com/maurolacy))
- Benchmark fixes / follow-up [\#62](https://github.com/babylonchain/babylon-contract/pull/62) ([maurolacy](https://github.com/maurolacy))
- Babylon contract benchmarks [\#61](https://github.com/babylonchain/babylon-contract/pull/61) ([maurolacy](https://github.com/maurolacy))
- Upgrade to latest rust-bitcoin 0.31.x [\#60](https://github.com/babylonchain/babylon-contract/pull/60) ([maurolacy](https://github.com/maurolacy))

## [v0.4.0](https://github.com/babylonchain/babylon-contract/tree/v0.4.0) (2024-02-13)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.3.0...v0.4.0)

**Merged pull requests:**

- Refactor: BTC light client header storage [\#57](https://github.com/babylonchain/babylon-contract/pull/57) ([maurolacy](https://github.com/maurolacy))
- More queries [\#56](https://github.com/babylonchain/babylon-contract/pull/56) ([maurolacy](https://github.com/maurolacy))

## [v0.3.0](https://github.com/babylonchain/babylon-contract/tree/v0.3.0) (2024-02-09)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.2.0...v0.3.0)

**Closed issues:**

- Get rid of Makefile [\#48](https://github.com/babylonchain/babylon-contract/issues/48)

**Merged pull requests:**

- Release 0.3 [\#58](https://github.com/babylonchain/babylon-contract/pull/58) ([maurolacy](https://github.com/maurolacy))
- Add queries [\#55](https://github.com/babylonchain/babylon-contract/pull/55) ([maurolacy](https://github.com/maurolacy))
- Update CI rust image to a more recent version \(1.75.0\) [\#54](https://github.com/babylonchain/babylon-contract/pull/54) ([maurolacy](https://github.com/maurolacy))
- Remove Makefile [\#53](https://github.com/babylonchain/babylon-contract/pull/53) ([maurolacy](https://github.com/maurolacy))
- BtcHeaders message handler [\#52](https://github.com/babylonchain/babylon-contract/pull/52) ([maurolacy](https://github.com/maurolacy))
- Fork choice tests [\#51](https://github.com/babylonchain/babylon-contract/pull/51) ([maurolacy](https://github.com/maurolacy))
- Fork choice rule impl [\#50](https://github.com/babylonchain/babylon-contract/pull/50) ([maurolacy](https://github.com/maurolacy))
- Point to public repo [\#47](https://github.com/babylonchain/babylon-contract/pull/47) ([maurolacy](https://github.com/maurolacy))
- Update cosmwasm [\#46](https://github.com/babylonchain/babylon-contract/pull/46) ([maurolacy](https://github.com/maurolacy))
- Upgrade comswasm to v1.5.1 [\#44](https://github.com/babylonchain/babylon-contract/pull/44) ([maurolacy](https://github.com/maurolacy))
- chore: bump Babylon with ABCI++ [\#41](https://github.com/babylonchain/babylon-contract/pull/41) ([SebastianElvis](https://github.com/SebastianElvis))
- Babylon tag format [\#40](https://github.com/babylonchain/babylon-contract/pull/40) ([maurolacy](https://github.com/maurolacy))

## [v0.2.0](https://github.com/babylonchain/babylon-contract/tree/v0.2.0) (2023-12-22)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.1.0...v0.2.0)

**Merged pull requests:**

- API adjustments / serialisation support [\#37](https://github.com/babylonchain/babylon-contract/pull/37) ([maurolacy](https://github.com/maurolacy))

## [v0.1.0](https://github.com/babylonchain/babylon-contract/tree/v0.1.0) (2023-12-21)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/975426f4cef50ce47610b51a55c576c5ddd1d39b...v0.1.0)

**Closed issues:**

- test: tests for Go \<-\> Rust serialisation [\#4](https://github.com/babylonchain/babylon-contract/issues/4)

**Merged pull requests:**

- bump Babylon proto files and verification rules [\#33](https://github.com/babylonchain/babylon-contract/pull/33) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: bump dependencies to {Babylon, optimiser, blst, cosmwasm} [\#32](https://github.com/babylonchain/babylon-contract/pull/32) ([SebastianElvis](https://github.com/SebastianElvis))
- CI: Push optimized smart contract to S3 [\#31](https://github.com/babylonchain/babylon-contract/pull/31) ([filippos47](https://github.com/filippos47))
- bump to Babylon v0.7.0 [\#29](https://github.com/babylonchain/babylon-contract/pull/29) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: apply fmt/clippy and solidify CI [\#28](https://github.com/babylonchain/babylon-contract/pull/28) ([SebastianElvis](https://github.com/SebastianElvis))
- feat: handler for BTC timestamps [\#26](https://github.com/babylonchain/babylon-contract/pull/26) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: improve error handling [\#24](https://github.com/babylonchain/babylon-contract/pull/24) ([SebastianElvis](https://github.com/SebastianElvis))
- CZ header chain: KVStore and handlers [\#23](https://github.com/babylonchain/babylon-contract/pull/23) ([SebastianElvis](https://github.com/SebastianElvis))
- epoch chain: reenable test for `ProofEpochSealed` [\#22](https://github.com/babylonchain/babylon-contract/pull/22) ([SebastianElvis](https://github.com/SebastianElvis))
- epoch chain: verifying a checkpoint is submitted to Bitcoin [\#21](https://github.com/babylonchain/babylon-contract/pull/21) ([SebastianElvis](https://github.com/SebastianElvis))
- epoch chain: verifying a sealed epoch [\#18](https://github.com/babylonchain/babylon-contract/pull/18) ([SebastianElvis](https://github.com/SebastianElvis))
- KVStore and basic logic for Babylon epoch chain [\#17](https://github.com/babylonchain/babylon-contract/pull/17) ([SebastianElvis](https://github.com/SebastianElvis))
- test: preliminary test for BTC light client [\#16](https://github.com/babylonchain/babylon-contract/pull/16) ([SebastianElvis](https://github.com/SebastianElvis))
- wasmbinding: functionalities for sending custom messages to Cosmos zone [\#15](https://github.com/babylonchain/babylon-contract/pull/15) ([SebastianElvis](https://github.com/SebastianElvis))
- btclightclient: DB schema for BTC light client, and basic logics [\#13](https://github.com/babylonchain/babylon-contract/pull/13) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: CI steup [\#11](https://github.com/babylonchain/babylon-contract/pull/11) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: Enable contract to be used as a dependency and add error module [\#10](https://github.com/babylonchain/babylon-contract/pull/10) ([vitsalis](https://github.com/vitsalis))
- bitcoin: importing `rust-bitcoin` [\#8](https://github.com/babylonchain/babylon-contract/pull/8) ([SebastianElvis](https://github.com/SebastianElvis))
- test: unit test for Go\<-\>Rust protobuf deserialisation [\#6](https://github.com/babylonchain/babylon-contract/pull/6) ([SebastianElvis](https://github.com/SebastianElvis))
- proto: protobuf messages for Babylon smart contract [\#5](https://github.com/babylonchain/babylon-contract/pull/5) ([SebastianElvis](https://github.com/SebastianElvis))
- vanilla contract [\#1](https://github.com/babylonchain/babylon-contract/pull/1) ([SebastianElvis](https://github.com/SebastianElvis))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
