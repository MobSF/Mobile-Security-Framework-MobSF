# Custom Test Plugins (30, 31)

- Plugin SDK located at `mobsf/plugins/sdk.py` with hooks for static/dynamic analyzers.
- Hybrid frameworks (React Native, Flutter) supported via language-specific analyzers.
- Integrations:
  - **Frida** scripts executed via `frida-server` container.
  - **JADX** for decompilation tasks.
  - **Burp Suite** proxy profile exported for dynamic interception.
- Plugins declare metadata including MASVS controls addressed and required capabilities.
