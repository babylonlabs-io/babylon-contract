# Changelog

## [Unreleased](https://github.com/babylonchain/babylon-contract/tree/HEAD)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.3.0...HEAD)

## [v0.3.0](https://github.com/babylonchain/babylon-contract/tree/v0.3.0) (2024-02-09)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.2.0...v0.3.0)

**Closed issues:**

- Get rid of Makefile [\#48](https://github.com/babylonchain/babylon-contract/issues/48)

**Merged pull requests:**

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
