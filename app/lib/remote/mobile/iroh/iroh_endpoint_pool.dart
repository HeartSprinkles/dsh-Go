/// Ref-counted, keyed sharing of expensive long-lived resources — used for the
/// iroh [Endpoint].
///
/// The iroh docs prefer one endpoint per application: it holds the relay
/// connection, the QUIC sockets and the address cache, so rebuilding it on every
/// reconnect loses work that the next dial then has to redo. A host link,
/// however, is created and disposed by the UI, and several links can share the
/// same identity. This pool gives each identity exactly one value, hands out
/// leases, and disposes the value when the last lease goes away.
///
/// [invalidate] is the escape hatch for a network change: the current value is
/// bound to sockets that no longer work, so it is closed now and the next
/// [acquire] builds a fresh one. Leases taken before the invalidation report
/// [IrohEndpointLease.isActive] false and cannot be used to dial.
library;

import 'dart:async';

/// One reference on a pooled value.
///
/// A lease must be [release]d exactly once; further calls are no-ops. After
/// [IrohEndpointPool.invalidate] the lease is still releasable but no longer
/// [isActive].
class IrohEndpointLease<T> {
  IrohEndpointLease._(this._pool, this._entry, this.key, this.value);

  final IrohEndpointPool<T> _pool;
  final _PoolEntry<T> _entry;

  /// The pool key this lease was taken under.
  final String key;

  /// The shared value.
  final T value;

  bool _released = false;

  /// False once the value was invalidated (a network change closed its sockets)
  /// or this lease was released. A stale lease must not dial.
  bool get isActive => !_released && !_entry.invalidated;

  /// Gives this reference back. The last lease of a generation disposes the
  /// value; the returned future completes when that disposal finished.
  Future<void> release() => _pool._release(this);

  /// Invalidates the whole generation this lease belongs to (all leases on the
  /// same key), so the next [IrohEndpointPool.acquire] creates a new value.
  Future<void> invalidate() => _pool.invalidate(key);

  bool _markReleased() {
    if (_released) return false;
    _released = true;
    return true;
  }
}

class _PoolEntry<T> {
  _PoolEntry(this.pending);

  final Future<T> pending;
  int leases = 0;
  bool invalidated = false;
}

/// Keyed, ref-counted pool. Concurrent acquires for one key share a single
/// creation, and a key is never re-created before its old value finished
/// closing — two live endpoints for one identity would fight over the same
/// sockets and relay registration.
class IrohEndpointPool<T> {
  IrohEndpointPool({this.create, required this.dispose});

  /// Default factory; [acquire] can pass one for a single call when the value
  /// depends on per-call material (the identity key).
  final Future<T> Function(String key)? create;
  final Future<void> Function(T value) dispose;

  final Map<String, _PoolEntry<T>> _entries = <String, _PoolEntry<T>>{};
  final Map<String, Future<void>> _closing = <String, Future<void>>{};

  /// How many values are currently alive (tests and diagnostics).
  int get liveCount => _entries.length;

  /// Takes a lease on the value for [key], creating it if this generation has
  /// none yet. [createOverride] replaces the pool factory for this call — the caller
  /// needs that when the value depends on per-call material (the identity key).
  Future<IrohEndpointLease<T>> acquire(String key, {Future<T> Function()? createOverride}) async {
    final closing = _closing[key];
    if (closing != null) {
      // Wait out the previous generation so two endpoints never hold sockets
      // for the same identity at once.
      await closing;
    }
    var entry = _entries[key];
    if (entry == null) {
      final Future<T> pending;
      if (createOverride != null) {
        pending = createOverride();
      } else {
        final factory = create;
        if (factory == null) throw StateError('no factory for $key');
        pending = factory(key);
      }
      entry = _PoolEntry<T>(pending);
      _entries[key] = entry;
      final created = entry;
      // A bind that throws must not poison the key: drop it so the next acquire
      // can retry instead of failing forever on a cached error.
      unawaited(pending.then<void>((_) {}, onError: (Object _) {
        if (identical(_entries[key], created)) _entries.remove(key);
      }));
    }
    final value = await entry.pending;
    entry.leases++;
    return IrohEndpointLease._(this, entry, key, value);
  }

  /// Drops the current generation for [key] and closes it; the returned future
  /// completes when the value is gone, and later acquires wait for it too.
  Future<void> invalidate(String key) {
    final entry = _entries.remove(key);
    if (entry == null) {
      final closing = _closing[key];
      return closing ?? Future<void>.value();
    }
    entry.invalidated = true;
    return _close(key, entry);
  }

  Future<void> _release(IrohEndpointLease<T> lease) {
    if (!lease._markReleased()) return Future<void>.value();
    final entry = lease._entry;
    if (entry.invalidated) return _closing[lease.key] ?? Future<void>.value();
    entry.leases--;
    if (entry.leases > 0) return Future<void>.value();
    if (identical(_entries[lease.key], entry)) _entries.remove(lease.key);
    return _close(lease.key, entry);
  }

  Future<void> _close(String key, _PoolEntry<T> entry) {
    final closing = entry.pending.then<void>((value) async {
      try {
        await dispose(value);
      } on Object {
        // Closing a dead endpoint must not fail the caller's teardown.
      }
    }, onError: (Object _) {
      // Creation already failed; there is nothing to dispose.
    });
    _closing[key] = closing;
    return closing.whenComplete(() {
      if (identical(_closing[key], closing)) _closing.remove(key);
    });
  }
}
