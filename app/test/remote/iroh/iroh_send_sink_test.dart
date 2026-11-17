import 'dart:async';

import 'package:dsh_app/remote/mobile/iroh/iroh_send_sink.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('writes are serialized and FIN waits for buffered writes', () async {
    final gate = Completer<void>();
    final events = <String>[];
    final sink = IrohSendSink(
      write: (data) async {
        events.add('start:${data.single}');
        if (data.single == 1) await gate.future;
        events.add('end:${data.single}');
      },
      finish: () async => events.add('fin'),
      onError: (e, s) => fail('$e'),
    );
    final buffer = <int>[1];
    sink.add(buffer);
    buffer[0] = 9;
    sink.add([2]);
    final closed = sink.close();
    await Future<void>.delayed(Duration.zero);
    expect(events, ['start:1']);
    gate.complete();
    await closed;
    expect(events, ['start:1', 'end:1', 'start:2', 'end:2', 'fin']);
    expect(() => sink.add([3]), throwsStateError);
    await sink.close();
  });

  test('write failure reaches done and stops subsequent writes and FIN', () async {
    final failure = StateError('peer reset');
    final errors = <Object>[];
    var writes = 0;
    var finishes = 0;
    final sink = IrohSendSink(
      write: (_) async {
        writes++;
        throw failure;
      },
      finish: () async {
        finishes++;
      },
      onError: (e, s) => errors.add(e),
    );
    final failed = expectLater(sink.done, throwsA(same(failure)));
    sink.add([1]);
    sink.add([2]);
    final closed = expectLater(sink.close(), throwsA(same(failure)));
    await failed;
    await closed;
    expect(errors, [failure]);
    expect(writes, 1);
    expect(finishes, 0);
  });

  test('done stays pending until finish completes', () async {
    final gate = Completer<void>();
    final sink = IrohSendSink(write: (_) async {}, finish: () => gate.future, onError: (e, s) => fail('$e'));
    var done = false;
    unawaited(
      sink.done.then((_) {
        done = true;
      }),
    );
    final closed = sink.close();
    await Future<void>.delayed(Duration.zero);
    expect(done, isFalse);
    gate.complete();
    await closed;
    expect(done, isTrue);
  });
}
