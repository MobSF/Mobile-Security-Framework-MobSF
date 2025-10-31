# Architecture Modernisation (10)

- Domain logic consolidated under `mobsf/core/` with service classes per analyzer.
- API layer uses DRF viewsets located in `mobsf/api/` with serializers decoupled from ORM.
- UI templates reside in `mobsf/templates/`; front-end assets compiled via Vite.
- Configuration centralised in `mobsf/conf/` with environment-driven settings.
- Utilities (crypto, file ops) extracted to `mobsf/utils/` with exhaustive unit tests.
