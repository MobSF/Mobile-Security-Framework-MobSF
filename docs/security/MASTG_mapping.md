# MASTG Test Coverage (26-33)

| Control | Automated Test | Location |
|---------|----------------|----------|
| MASTG-AUTH-1 | `tests/security/test_auth_hardening.py::test_mfa_enforced` | Auth package |
| MASTG-STORAGE-1 | `tests/storage/test_encrypted_keystore.py` | Storage module |
| MASTG-CRYPTO-1 | `tests/crypto/test_cipher_usage.py` | Crypto utils |
| MASTG-NET-1 | `tests/network/test_tls_pinning.py` | Network analyzer |
| MASVS V2 Control | `tests/masvs/test_quick_check.py` | Quick check CLI |

Dynamic tests executed via `scripts/run_mastg_suite.sh` producing JSON reports consumed by the dashboard widgets.
