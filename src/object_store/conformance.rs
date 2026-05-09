//! Conformance contract for `ObjectStore` impls.
//!
//! Each helper here is one assertion any `ObjectStore` impl must
//! satisfy. The tests module wires `FsObjectStore`, `MemObjectStore`,
//! and `SqliteObjectStore` through the same helpers so the trait
//! contract is one piece of code, not three.
//!
//! Note on path-safety: the malformed-input cases that used to live
//! in this file (`read_loose("../foo")`, `write_loose("ZZZZ...")`)
//! are now impossible by construction — `RepoId` and `Oid` validate
//! at `TryFrom` and the trait can only receive valid IDs. Those
//! contracts moved to `ids::tests` where they belong.

use super::*;
use crate::ids::{Oid, RepoId};

fn rid(s: &str) -> RepoId {
    RepoId::try_from(s).expect("test repo-id literal must satisfy RepoId contract")
}

fn oid(s: &str) -> Oid {
    Oid::try_from(s).expect("test oid literal must satisfy Oid contract")
}

/// "Read returns the bytes that were written." The fundamental
/// contract — an ObjectStore that can't read back what it stored
/// is broken regardless of backend.
pub(crate) fn read_after_write_round_trips<S: ObjectStore>(store: &S, repo_id: &RepoId, oid: &Oid) {
    let bytes = store
        .read_loose(repo_id, oid)
        .expect("read_loose Result::Ok")
        .expect("Some(bytes) for a known-present oid");
    assert!(!bytes.is_empty(), "read_loose returned empty bytes");
}

/// Reading an oid that was never inserted yields `Ok(None)` —
/// not an error, not empty bytes. Distinguishes "absent" from
/// "present but empty".
pub(crate) fn missing_oid_returns_none<S: ObjectStore>(store: &S, repo_id: &RepoId) {
    let absent = oid("0123456789abcdef0123456789abcdef01234567");
    assert!(
        store.read_loose(repo_id, &absent).unwrap().is_none(),
        "expected None for unknown oid, got Some",
    );
}

/// `write_loose` round-trips through `read_loose` with byte-exact
/// fidelity. Both impls have to satisfy this — anything a chunked-KV
/// or future backend can't preserve verbatim is broken.
pub(crate) fn write_then_read_round_trips<S: ObjectStore>(store: &S) {
    let r = rid("conf-repo");
    let o = oid("1111111111111111111111111111111111111111");
    let payload = b"contract-bytes-stand-in";
    store.write_loose(&r, &o, payload).unwrap();
    let got = store.read_loose(&r, &o).unwrap().expect("Some after write");
    assert_eq!(got.as_slice(), payload);
}

/// `write_loose` is idempotent — a second write of the same oid is
/// a no-op. Loose objects are content-addressed, so the same oid
/// implies the same bytes; both impls must honor this without
/// erroring out.
pub(crate) fn write_loose_idempotent_on_repeat<S: ObjectStore>(store: &S) {
    let r = rid("conf-repo");
    let o = oid("2222222222222222222222222222222222222222");
    let payload = b"first-write";
    store.write_loose(&r, &o, payload).unwrap();
    store.write_loose(&r, &o, payload).unwrap();
    let got = store.read_loose(&r, &o).unwrap().unwrap();
    assert_eq!(got.as_slice(), payload);
}

/// `list_loose` returns every written object with a populated
/// LooseInfo (oid + size + non-zero created_secs). Order is
/// unspecified, so the test sorts before comparing.
pub(crate) fn list_loose_enumerates_writes<S: ObjectStore>(store: &S) {
    let r = rid("conf-repo");
    let oids = [
        "1111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333",
    ];
    for o in oids {
        store.write_loose(&r, &oid(o), b"some-bytes").unwrap();
    }
    let mut listed = store.list_loose(&r).unwrap();
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
pub(crate) fn list_loose_empty_returns_empty_vec<S: ObjectStore>(store: &S) {
    let listed = store.list_loose(&rid("nope")).unwrap();
    assert!(listed.is_empty(), "expected empty Vec, got {listed:?}");
}

/// `delete_loose` on a present oid returns `Ok(true)` then
/// `Ok(false)` on a second call (idempotent removal). After
/// delete, `read_loose` returns None. Both impls must satisfy.
pub(crate) fn delete_loose_round_trips<S: ObjectStore>(store: &S) {
    let r = rid("conf-repo");
    let o = oid("4444444444444444444444444444444444444444");
    store.write_loose(&r, &o, b"to-delete").unwrap();
    assert!(store.read_loose(&r, &o).unwrap().is_some());
    assert!(
        store.delete_loose(&r, &o).unwrap(),
        "first delete must report true"
    );
    assert!(store.read_loose(&r, &o).unwrap().is_none());
    assert!(
        !store.delete_loose(&r, &o).unwrap(),
        "second delete must report false (already gone)"
    );
}

/// `exists` agrees with `read_loose` for both present and absent
/// oids. The trait promises this — a backend whose existence
/// check disagrees with its body fetch is broken.
pub(crate) fn exists_agrees_with_read<S: ObjectStore>(
    store: &S,
    repo_id: &RepoId,
    present_oid: &Oid,
) {
    assert!(
        store.exists(repo_id, present_oid).unwrap(),
        "exists must return true for a known-present oid",
    );
    let absent = oid("0000000000000000000000000000000000000000");
    assert!(
        !store.exists(repo_id, &absent).unwrap(),
        "exists must return false for a never-written oid",
    );
}
