# Scope and safeguards

This toolkit implements the non-executing setup and evidence-collection portion
of an Octra source investigation.

Included:

- local workspace creation;
- fetching explicitly declared public Git repositories;
- recording checked-out source revisions;
- recursive source file inventory and SHA-256 digests;
- checksum verification for artifacts that the operator already possesses;
- JSON metadata extraction and a clearly labelled heuristic block-duplicate scan.

Explicitly excluded:

- running scripts, binaries, wallet generators, build targets, or nodes from a
  cloned repository;
- submodule initialisation, container execution, service changes, cron jobs, or
  firewall/VPS configuration;
- fetching deleted private content, credential material, secrets, or keys;
- cryptanalytic recovery, side-channel experiments, exploit development, or
  interaction with a live network.

Use only with public material or data you are authorized to analyze. Static
collection results are evidence inputs, not vulnerability conclusions.
