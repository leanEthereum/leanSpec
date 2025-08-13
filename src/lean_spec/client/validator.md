# Validator

## Validator identification

Validators are defined as a list of their ENRs in a yaml file named `validators.yaml`.

```yaml
- enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg
- enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg
- enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg
```

The validator ID is the zero-index of the list in the yaml file. For example,
`3.17.30.69`, `54.178.44.198`, `18.216.248.220` are `validator_id: 0`,
`validator_id: 1`, `validator_id: 2` respectively.

Because pqsignature has not been implemented yet, the `secp256k1` field will
still be the 33 bytes compressed secp256k1 public key for the time being
and shall be replaced in subsequent devnet iterations.

## Block proposer selection

The block proposer shall be determined by the modulo of current slot number by
the total number of validators, such that block proposers are determined in
a round-robin manner of the validator IDs.

```py
def is_proposer(state: BeaconState, validator_index: ValidatorIndex) -> bool:
    return get_current_slot() % state.config.num_validators == validator_index
```

To ensure block proposal duties are distributed equally between 2 participating
clients, the validator IDs may be assigned to 2 clients in odd/even manner.
