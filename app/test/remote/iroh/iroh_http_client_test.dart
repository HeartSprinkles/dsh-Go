import 'package:dsh_app/remote/mobile/iroh/iroh_http_client.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('a tunnel never falls back to system roots when its pinned CA is lost', () {
    for (final pem in ['', '  \n']) {
      expect(() => buildIrohHttpClient(pem, 12345), throwsArgumentError);
    }
  });
}
