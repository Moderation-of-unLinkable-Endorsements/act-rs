# Test vectors

`draft-L4.txt` is the Test Vectors appendix of draft-authors-mole-act at
commit a7ba1c0561b4465a2ebeac5719ffdd7b562db3e9. The `act-L*.txt` files were
generated from the draft's Python reference implementation at the same commit
by `generate.py`, which documents the exact invocations. `src/tests/vectors.rs`
replays every `rand` entry in place of the random number generator and checks
each key, message, state, and Credential byte for byte, on every backend.

`draft-L4.txt` is reproduced from the Internet-Draft, whose test vectors are
subject to the IETF Trust's legal provisions; the generated files are
covered by this repository's license.
