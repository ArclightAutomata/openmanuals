//! JS bindings of openmanuals-strip, kept apart from openmanuals-wasm so the service worker
//! does not load lopdf. Loaded only by the extension's stripper worker.
//!
//! A panic aborts on wasm32 (it cannot be caught): the call throws a
//! `WebAssembly.RuntimeError` and the instance must not be used again. The
//! panic message goes to `console.error` first.
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn error(msg: &str);
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from(js_sys::Error::new(&e.to_string()))
}

fn set(o: &Object, k: &str, v: impl Into<JsValue>) {
    Reflect::set(o, &JsValue::from_str(k), &v.into()).expect("set on a plain object");
}

#[wasm_bindgen(start)]
fn start() {
    std::panic::set_hook(Box::new(|info| {
        error(&format!("openmanuals-strip panicked: {info}"))
    }));
}

/// `openmanuals-strip`: the tool name recorded on derivation facts.
#[wasm_bindgen]
pub fn strip_tool() -> String {
    openmanuals_strip::STRIP_TOOL.into()
}

/// `om-strip-rs/2`: recorded on derivation facts as `tool_version`.
#[wasm_bindgen]
pub fn strip_version() -> String {
    openmanuals_strip::STRIP_VERSION.into()
}

/// Strip a PDF. Returns `{ changed, bytes, log }`; `bytes` (a Uint8Array) is
/// set only when `changed` is true, so an unchanged file is not copied back.
/// Throws on unreadable input.
#[wasm_bindgen(unchecked_return_type = "{ changed: boolean; bytes?: Uint8Array; log: string[] }")]
pub fn strip(input: &[u8]) -> Result<JsValue, JsValue> {
    let r = openmanuals_strip::strip(input).map_err(js_err)?;
    let o = Object::new();
    set(&o, "changed", r.changed);
    if r.changed {
        set(&o, "bytes", Uint8Array::from(&r.bytes[..]));
    }
    set(
        &o,
        "log",
        r.log
            .iter()
            .map(|l| JsValue::from_str(l))
            .collect::<Array>(),
    );
    Ok(o.into())
}

/// Inspect a PDF without changing it (tests): `{ pages, leading, trailing,
/// footer_pages, manualslib_links }`. Throws on unreadable input.
#[wasm_bindgen(
    unchecked_return_type = "{ pages: number; leading: number; trailing: number; footer_pages: number; manualslib_links: number }"
)]
pub fn inspect(input: &[u8]) -> Result<JsValue, JsValue> {
    let i = openmanuals_strip::inspect(input).map_err(js_err)?;
    let o = Object::new();
    set(&o, "pages", i.pages as u32);
    set(&o, "leading", i.wrapper.0 as u32);
    set(&o, "trailing", i.wrapper.1 as u32);
    set(&o, "footer_pages", i.footer_pages as u32);
    set(&o, "manualslib_links", i.manualslib_links as u32);
    Ok(o.into())
}

/// Panics on purpose, so tests can check that a trapped instance is replaced.
#[doc(hidden)]
#[wasm_bindgen]
pub fn __panic_for_tests() {
    panic!("deliberate panic for tests");
}
