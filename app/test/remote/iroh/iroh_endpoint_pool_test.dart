import 'dart:async';

import 'package:dsh_app/remote/mobile/iroh/iroh_endpoint_pool.dart';
import 'package:flutter_test/flutter_test.dart';

/// A stand-in for the native endpoint: only the pool's bookkeeping matters here.
class _Value {
  _Value(this.key, this.generation);

  final String key;
  final int generation;
  bool closed = false;
}

void main() {
  late List<_Value> created;
  late List<_Value> disposed;
  late Completer<void>? gate;

  IrohEndpointPool<_Value> newPool() => IrohEndpointPool<_Value>(
    create: (key) async {
      final value = _Value(key, created.length);
      created.add(value);
      final wait = gate;
      if (wait != null) await wait.future;
      return value;
    },
    dispose: (value) async {
      value.closed = true;
      disposed.add(value);
    },
  );

  setUp(() {
    created = <_Value>[];
    disposed = <_Value>[];
    gate = null;
  });

  test('concurrent acquires for one key create a single value', () async {
    final pool = newPool();
    final leases = await Future.wait([pool.acquire('a'), pool.acquire('a'), pool.acquire('a')]);

    expect(created, hasLength(1));
    expect(leases.map((l) => l.value), everyElement(same(created.single)));
    expect(leases.every((l) => l.isActive), isTrue);
    expect(pool.liveCount, 1);
  });

  test('two keys never share a value', () async {
    final pool = newPool();
    final a = await pool.acquire('a');
    final b = await pool.acquire('b');

    expect(created, hasLength(2));
    expect(a.value, isNot(same(b.value)));
    expect(pool.liveCount, 2);
  });

  test('the value is disposed only when the last lease is released', () async {
    final pool = newPool();
    final first = await pool.acquire('a');
    final second = await pool.acquire('a');

    await first.release();
    expect(disposed, isEmpty, reason: 'one reference is still live');
    expect(second.isActive, isTrue);

    await second.release();
    expect(disposed.single, same(created.single));
    expect(pool.liveCount, 0);
  });

  test('releasing twice only releases once', () async {
    final pool = newPool();
    final a = await pool.acquire('a');
    final b = await pool.acquire('a');

    await a.release();
    await a.release();
    expect(disposed, isEmpty);
    await b.release();
    expect(disposed, hasLength(1));
  });

  test('a failed create is forgotten so a later acquire can retry', () async {
    var attempts = 0;
    final pool = IrohEndpointPool<_Value>(
      create: (key) async {
        attempts++;
        if (attempts == 1) throw StateError('no runtime');
        return _Value(key, 0);
      },
      dispose: (value) async => disposed.add(value),
    );

    await expectLater(pool.acquire('a'), throwsStateError);
    final lease = await pool.acquire('a');
    expect(lease.value.key, 'a');
    expect(attempts, 2);
  });

  test('invalidate closes the generation and makes its leases stale', () async {
    final pool = newPool();
    final lease = await pool.acquire('a');

    await pool.invalidate('a');

    expect(lease.isActive, isFalse);
    expect(created.single.closed, isTrue);
    expect(pool.liveCount, 0);
  });

  test('acquire waits for the invalidated generation to close before binding again', () async {
    final pool = newPool();
    final lease = await pool.acquire('a');
    expect(lease.isActive, isTrue);

    final closing = pool.invalidate('a');
    final next = pool.acquire('a');
    await closing;
    final reborn = await next;

    expect(created, hasLength(2));
    expect(created.first.closed, isTrue, reason: 'the old sockets are gone before the new dial');
    expect(reborn.value, same(created.last));
    expect(reborn.isActive, isTrue);
  });

  test('a lease released after invalidation does not dispose the new generation', () async {
    final pool = newPool();
    final lease = await pool.acquire('a');
    await pool.invalidate('a');
    final reborn = await pool.acquire('a');

    await lease.release();

    expect(created.last.closed, isFalse);
    expect(reborn.isActive, isTrue);
    await reborn.release();
    expect(created.last.closed, isTrue);
  });
}
