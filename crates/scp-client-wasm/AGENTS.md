# scp-client-wasm

`JsValue::from`, `JsError::new`, and every conversion into them call wasm-bindgen imports that panic when the code runs off `wasm32`, so a host `#[test]` cannot exercise the `Err` arm of a `#[wasm_bindgen]` function. Test the underlying validator, which returns a plain Rust error, and test the `Ok` arm through the wrapper.
