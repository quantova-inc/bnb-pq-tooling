// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::missing_safety_doc)]

use core::slice;
use qtv_crypto::{ml_dsa, ml_dsa_87, slh_dsa};
use std::panic::{catch_unwind, AssertUnwindSafe};

const VALID: i32 = 1;
const INVALID: i32 = 0;

unsafe fn as_bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

#[no_mangle]
pub unsafe extern "C" fn qc_verify_ml_dsa_65(pk: *const u8, pk_len: usize, msg: *const u8, msg_len: usize, sig: *const u8, sig_len: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let pk = match unsafe { as_bytes(pk, pk_len) } { Some(v) => v, None => return INVALID };
        let msg = match unsafe { as_bytes(msg, msg_len) } { Some(v) => v, None => return INVALID };
        let sig = match unsafe { as_bytes(sig, sig_len) } { Some(v) => v, None => return INVALID };
        let pk: &ml_dsa::PublicKey = match pk.try_into() { Ok(v) => v, Err(_) => return INVALID };
        let sig: &ml_dsa::Signature = match sig.try_into() { Ok(v) => v, Err(_) => return INVALID };
        if ml_dsa::verify_strict(pk, msg, sig, &[]) { VALID } else { INVALID }
    })).unwrap_or(INVALID)
}

#[no_mangle]
pub unsafe extern "C" fn qc_verify_ml_dsa_87(pk: *const u8, pk_len: usize, msg: *const u8, msg_len: usize, sig: *const u8, sig_len: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let pk = match unsafe { as_bytes(pk, pk_len) } { Some(v) => v, None => return INVALID };
        let msg = match unsafe { as_bytes(msg, msg_len) } { Some(v) => v, None => return INVALID };
        let sig = match unsafe { as_bytes(sig, sig_len) } { Some(v) => v, None => return INVALID };
        let pk: &ml_dsa_87::PublicKey = match pk.try_into() { Ok(v) => v, Err(_) => return INVALID };
        let sig: &ml_dsa_87::Signature = match sig.try_into() { Ok(v) => v, Err(_) => return INVALID };
        if ml_dsa_87::verify_strict(pk, msg, sig, &[]) { VALID } else { INVALID }
    })).unwrap_or(INVALID)
}

#[no_mangle]
pub unsafe extern "C" fn qc_verify_slh_dsa(pk: *const u8, pk_len: usize, msg: *const u8, msg_len: usize, sig: *const u8, sig_len: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let pk = match unsafe { as_bytes(pk, pk_len) } { Some(v) => v, None => return INVALID };
        let msg = match unsafe { as_bytes(msg, msg_len) } { Some(v) => v, None => return INVALID };
        let sig = match unsafe { as_bytes(sig, sig_len) } { Some(v) => v, None => return INVALID };
        if sig.len() != slh_dsa::SIGNATURE_BYTES { return INVALID; }
        let pk: &[u8; slh_dsa::PUBLIC_KEY_BYTES] = match pk.try_into() { Ok(v) => v, Err(_) => return INVALID };
        if slh_dsa::verify(pk, msg, sig, &[]) { VALID } else { INVALID }
    })).unwrap_or(INVALID)
}
