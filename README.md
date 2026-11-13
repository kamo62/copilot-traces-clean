# Traces Clean

A headless, open-source backend for collecting authorised GitHub Copilot records,
investigating client telemetry and preparing versioned research exports. It is
intended to help examine observed developer requests, context retrieval and tool
orchestration without treating those observations as developer performance scores.

Application version: `0.0.1`. This is an early source-only edition, not a deployed
service, approved dataset or guarantee of complete conversation capture.

## Capabilities in the source

- Enterprise record collection with stable identifiers, checksums and database
  checkpoints. Automatic collection is disabled by default in this edition.
- ClickHouse storage for complete returned record objects and OTLP JSON batches.
- Separate admin, status, research and OTLP bearer roles.
- Parsing for supported JSON and streaming response shapes, with explicit gaps
  for malformed, truncated, withheld and unsupported content.
- Versioned research revisions, deterministic sanitisation, scoped references,
  bounded processing and a manual release gate.
- Bounded JSONL/gzip export pages with revision-pinned cursors and manifests.
- Offline reader, coverage and privacy-evaluation utilities.
- Locally served Swagger API documentation. There is no custom frontend.

Research output is pseudonymised, not guaranteed anonymous. A stream-end marker
does not prove a full conversation. Matching text does not establish message
identity. Optional identity/content-repeat processing and assisted detection
remain disabled by default; content-repeat annotations do not suppress payloads.

## Safe defaults and data isolation

This edition includes no collected employee traces, database dumps, private
policies, credentials, deployment evidence or server connection helper.

- Compose project: `traces-clean`.
- Database volume: `traces-clean-clickhouse-data`.
- Local API image: `traces-clean-native-records:local`.
- All published ports bind to loopback.
- Default collection enterprise: `example-enterprise`, not a configured organisation.
- Automatic collection is off, the research worker is opt-in and release is held.
- No existing deployment or database was contacted when preparing this source.

| Interface | Default local endpoint |
|---|---|
| ClickHouse HTTP/SQL | `127.0.0.1:13320` |
| Records API and `/docs` | `127.0.0.1:13330` |
| OTLP HTTP | `127.0.0.1:14328` |
| OTLP gRPC | `127.0.0.1:14327` |

Do not point this copy at an existing production database or reuse another
deployment's private files. Docker volumes are durable state, not backups.
Removing a volume destroys its data.

## Development

The application and offline Python utilities use the standard library. The API
container declares Python 3.13. Use an already installed compatible Python for
local development; no package installation is needed for the existing unit setup.

Some inherited checks still reference the previous application version or research
documentation excluded from this edition. They have deliberately not been changed
here, and no passing suite is claimed for this snapshot. Parser, sanitiser and
event-schema versions retain their independent values; they are not application
release numbers.

Offline command help reads no source dataset:

```sh
python3 -B clients/research_reader.py --help
python3 -B clients/conversation_coverage.py --help
python3 -B clients/privacy_eval.py --help
```

These utilities take explicit local input files. Do not provide private agent
history, employee records or a live database as development fixtures.

## Runtime prerequisites

The full stack requires Docker/Compose and locally available ClickHouse,
OpenTelemetry Collector and Python images. Building or pulling missing images is
not an offline operation. No container build or runtime verification is claimed
for this edition.

`python3 setup.py` prepares private local credentials and a policy file. It does
not start services. Keep `.env`, token files and `private/` out of Git. Compose
currently also requires a private `.github-token` file even when automatic polling
is disabled. Do not put a real token into the example configuration.

Collection or client capture requires explicit authorisation, appropriate source
permissions and an intentionally configured endpoint. Supplied client settings
are examples, not instructions to enable content capture across a workforce.
The database and verification scripts are operational tools, not offline demos.

## Research release limits

Keep release on HOLD until source authority, disclosure policy, retention choices,
processing integrity and an independent privacy review have been established.
Automated sanitisation and passing development checks do not supply consent,
commercial rights, anonymity or marketplace acceptance.

No dataset upload, marketplace connector, model training, automatic retention
deletion or automatic research publication is provided by this edition.

## Code layout

- `native/source/api/`: collection, parsing, sanitisation, research, review and HTTP APIs.
- `native/source/tests/`: inherited unit and separate integration checks.
- `clients/`: explicit-file offline readers/evaluators and optional client configuration.
- `clickhouse/`: database resource configuration.
- `compose.yaml` and `otelcol-config.yaml`: runtime wiring.
- `setup.py`: private configuration preparation.
- `verify.py` and `check_ssd.py`: deployment checks, not offline sample-data tools.

## Licence

Application code is [MIT](LICENSE). Swagger UI assets are vendored from
`swagger-ui-dist@5.33.2` and retain their Apache 2.0 licence, NOTICE and bundled
dependency licence file under `native/source/api/docs/assets/`. Those legal
notices must remain in source archives. This code licence does not grant rights
to any trace content, employer/client material or external dataset.
