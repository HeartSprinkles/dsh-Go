import 'dart:async';
import 'dart:typed_data';

/// Serializes QUIC writes, including FIN, across the asynchronous FFI boundary.
/// The callbacks also let tests exercise flow control without a native endpoint.
class IrohSendSink implements StreamSink<List<int>> {
  IrohSendSink({required this.write, required this.finish, required this.onError}) {
    // Socket forwarding uses add(), not done. Keep failures observed even when
    // no caller awaits done; callers that do await it still receive the error.
    unawaited(_done.future.catchError((Object _) {}));
  }

  final Future<void> Function(List<int>) write;
  final Future<void> Function() finish;
  final void Function(Object, StackTrace) onError;
  final _done = Completer<void>();
  Future<void> _tail = Future<void>.value();
  bool _closed = false;
  bool _failed = false;

  void _enqueue(Future<void> Function() operation) {
    _tail = _tail.then((_) async {
      if (_failed) return;
      try {
        await operation();
      } catch (error, stack) {
        _fail(error, stack);
      }
    });
  }

  void _fail(Object error, StackTrace stack) {
    if (_failed || _done.isCompleted) return;
    _failed = true;
    _closed = true;
    _done.completeError(error, stack);
    onError(error, stack);
  }

  @override
  void add(List<int> data) {
    if (_closed) throw StateError('Cannot add to a closed iroh stream');
    // The producer may reuse its buffer before flow control releases the write.
    final copy = Uint8List.fromList(data);
    _enqueue(() => write(copy));
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {
    _fail(error, stackTrace ?? StackTrace.current);
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final data in stream) {
      add(data);
      await _tail;
      if (_failed) await done;
    }
  }

  @override
  Future<void> close() {
    if (!_closed) {
      _closed = true;
      _enqueue(() async {
        await finish();
        if (!_done.isCompleted) _done.complete();
      });
    }
    return done;
  }

  @override
  Future<void> get done => _done.future;
}
