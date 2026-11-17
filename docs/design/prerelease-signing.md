# Fork prerelease identity and signing

- Application ID: `io.github.ccch1mneyyy.dsh_app.test` (official: `io.github.ccch1mneyyy.dsh_app`). Both install side by side.
- Key alias: `dsh-go-prerelease`; dedicated RSA-3072 certificate, not the official release key.
- Certificate SHA-256: `BF:4B:5F:22:0E:21:FE:ED:52:A1:0D:53:1A:BA:59:57:73:73:CA:05:5F:CA:D7:FE:6A:1A:B9:02:94:81:2B:BF`.
- GitHub Secrets: `PRERELEASE_KEYSTORE_BASE64`, `PRERELEASE_STORE_PASSWORD`, `PRERELEASE_KEY_PASSWORD`, `PRERELEASE_KEY_ALIAS`. Never commit their values.
- Test APK workflow requires these secrets and checks the APK certificate and package before upload. Publish workflow rejects other certificates.
- Keep this key permanently. Never generate a replacement on CI. The same application ID, signing key and increasing versionCode allow in-place upgrades without deleting data.
- Earlier debug-signed `.test` APKs cannot be upgraded with this new key: uninstall the old test build first after backing up its data. The official app is unaffected.
