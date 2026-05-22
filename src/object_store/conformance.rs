//! Conformance contract for `ObjectStore` impls.
//!
//! Each helper here is one assertion any `ObjectStore` impl must
//! satisfy. The tests module wires `FsObjectStore`, `MemObjectStore`,
//! and `SqliteObjectStore` through the same helpers so the trait
//! contract is one piece of code, not three.
//!
//! Module-private to `object_store`. A future external test that
//! wants to run a new backend through the same contract can call
//! the helpers via `crate::object_store::conformance::*` after
//! widening visibility.

#![cfg(test)]

use super::*;

/// "Read returns the bytes that were written." The fundamental
/// contract — an ObjectStore that can't read back what it stored
/// is broken regardless of backend.
pub fn read_after_write_round_trips<S: ObjectStore>(store: &S, repo_id: &str, oid: &str) {
    let bytes = store
        .read_loose(repo_id, oid)
        .expect("read_loose Result::Ok")
        .expect("Some(bytes) for a known-present oid");
    assert!(!bytes.is_empty(), "read_loose returned empty bytes");
}

/// Reading an oid that was never inserted yields `Ok(None)` —
/// not an error, not empty bytes. Distinguishes "absent" from
/// "present but empty".
pub fn missing_oid_returns_none<S: ObjectStore>(store: &S, repo_id: &str) {
    let absent = "0123456789abcdef0123456789abcdef01234567";
    assert!(
        store.read_loose(repo_id, absent).unwrap().is_none(),
        "expected None for unknown oid, got Some",
    );
}

/// Malformed oids (path-traversal, wrong length, non-hex) yield
/// `Ok(None)` — never an error, never a stored value, never a
/// computed path that escapes the store. This is the trait's
/// path-safety contract.
pub fn malformed_oid_returns_none<S: ObjectStore>(store: &S) {
    // Path-traversal attempt.
    assert!(store
        .read_loose("repo", "../something/with/slash/and/some/more/x")
        .unwrap()
        .is_none());
    // Wrong length.
    assert!(store.read_loose("repo", "abc").unwrap().is_none());
    // Non-hex (uppercase Z).
    assert!(store
        .read_loose("repo", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
        .unwrap()
        .is_none());
}

/// `write_loose` round-trips through `read_loose` with byte-exact
/// fidelity. Both impls have to satisfy this — anything a chunked-KV
/// or future backend can't preserve verbatim is broken.
pub fn write_then_read_round_trips<S: ObjectStore>(store: &S) {
    // Use a synthetic 40-hex oid; both impls treat it as opaque
    // key-value lookup, so the FS impl's loose-format expectation
    // doesn't apply to the trait contract test.
    let oid = "1111111111111111111111111111111111111111";
    let payload = b"contract-bytes-stand-in";
    store.write_loose("conf-repo", oid, payload).unwrap();
    let got = store
        .read_loose("conf-repo", oid)
        .unwrap()
        .expect("Some after write");
    assert_eq!(got.as_slice(), payload);
}

/// `write_loose` is idempotent — a second write of the same oid is
/// a no-op. Loose objects are content-addressed, so the same oid
/// implies the same bytes; both impls must honor this without
/// erroring out.
pub fn write_loose_idempotent_on_repeat<S: ObjectStore>(store: &S) {
    let oid = "2222222222222222222222222222222222222222";
    let payload = b"first-write";
    store.write_loose("conf-repo", oid, payload).unwrap();
    // Second write of the same oid + bytes — must not error.
    store.write_loose("conf-repo", oid, payload).unwrap();
    let got = store.read_loose("conf-repo", oid).unwrap().unwrap();
    assert_eq!(got.as_slice(), payload);
}

/// `write_loose` with a malformed oid is a hard error, not a
/// silent drop. Reads of malformed oids return `Ok(None)` (the
/// path-safety contract), but writes need to surface the bug —
/// callers want to know rather than silently lose data.
pub fn write_loose_rejects_malformed_oid<S: ObjectStore>(store: &S) {
    let cases = [
        "../something",
        "abc",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ];
    for bad in cases {
        let r = store.write_loose("repo", bad, b"x");
        assert!(
            r.is_err(),
            "expected write_loose({bad:?}) to error, got {r:?}"
        );
    }
}

/// `list_loose` returns every written object with a populated
/// LooseInfo (oid + size + non-zero created_secs). Order is
/// unspecified, so the test sorts before comparing.
pub fn list_loose_enumerates_writes<S: ObjectStore>(store: &S) {
    let oids = [
        "1111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333",
    ];
    for oid in oids {
        store.write_loose("conf-repo", oid, b"some-bytes").unwrap();
    }
    let mut listed = store.list_loose("conf-repo").unwrap();
    listed.sort_by(|a, b| a.oid.cmp(&b.oid));
    let listed_oids: Vec<&str> = listed.iter().map(|i| i.oid.as_str()).collect();
    assert_eq!(listed_oids, oids);
    for info in &listed {
        assert!(info.size > 0, "size must be populated, got {info:?}");
        assert!(
            info.created_secs > 0,
            "created_secs must be populated, got {info:?}"
        );
    }
}

/// `list_loose` on an empty / unknown repo returns `Ok(vec![])` —
/// not an error. This matches the FS shape where `objects/` may
/// not exist yet and the chunked-KV shape where the repo's row
/// set is empty.
pub fn list_loose_empty_returns_empty_vec<S: ObjectStore>(store: &S) {
    let listed = store.list_loose("nope").unwrap();
    assert!(listed.is_empty(), "expected empty Vec, got {listed:?}");
}

/// `delete_loose` on a present oid returns `Ok(true)` then
/// `Ok(false)` on a second call (idempotent removal). After
/// delete, `read_loose` returns None. Both impls must satisfy.
pub fn delete_loose_round_trips<S: ObjectStore>(store: &S) {
    let oid = "4444444444444444444444444444444444444444";
    store.write_loose("conf-repo", oid, b"to-delete").unwrap();
    assert!(store.read_loose("conf-repo", oid).unwrap().is_some());
    assert!(
        store.delete_loose("conf-repo", oid).unwrap(),
        "first delete must report true"
    );
    assert!(store.read_loose("conf-repo", oid).unwrap().is_none());
    assert!(
        !store.delete_loose("conf-repo", oid).unwrap(),
        "second delete must report false (already gone)"
    );
}

/// `delete_loose` with a malformed oid is a hard error — same
/// shape as `write_loose`. We won't computed-path-escape on
/// the way out any more than on the way in.
pub fn delete_loose_rejects_malformed_oid<S: ObjectStore>(store: &S) {
    for bad in [
        "../something",
        "abc",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ] {
        let r = store.delete_loose("repo", bad);
        assert!(
            r.is_err(),
            "expected delete_loose({bad:?}) to error, got {r:?}"
        );
    }
}

/// `exists` agrees with `read_loose` for both present and absent
/// oids. The trait promises this — a backend whose existence
/// check disagrees with its body fetch is broken.
pub fn exists_agrees_with_read<S: ObjectStore>(store: &S, repo_id: &str, present_oid: &str) {
    assert!(
        store.exists(repo_id, present_oid).unwrap(),
        "exists must return true for a known-present oid",
    );
    let absent = "0000000000000000000000000000000000000000";
    assert!(
        !store.exists(repo_id, absent).unwrap(),
        "exists must return false for a never-written oid",
    );
    // Malformed oid: same shape as read_loose — false, not an error.
    assert!(
        !store.exists(repo_id, "not-a-real-oid").unwrap(),
        "exists must return false for a malformed oid",
    );
}
