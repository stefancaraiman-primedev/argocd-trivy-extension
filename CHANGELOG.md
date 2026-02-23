# Changelog

## v0.2.2 2026-02-23

- `Fix`: VulnerabilityReport lookup for workloads with long names (e.g. avokado-ai-streaming-processor). When the report name exceeds 63 characters, Trivy Operator uses a hash-based name. The extension now falls back to finding reports via Argo CD resource-tree and matching by labels (trivy-operator.resource.kind, trivy-operator.resource.name, trivy-operator.resource.namespace, trivy-operator.container.name) when direct fetch fails.

## v0.2.1 2024-05-13

- Fix: sorting order for severity column

## v0.2.0 2024-04-13

- `Enhancement`: Allow reports display for pods with multiple containers
- Minor styling updates to improve dark theme visibility

## v0.1.0 2024-04-07

- Initial release
