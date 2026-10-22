# Repository notes

The cryptographic backend code shared by `act-rs` and `ihat-rs` is hosted in
`ihat-rs`'s `backend` module. Reuse that implementation rather than duplicating
common backend code here; this crate should contain only ACT-specific backend
extensions.
