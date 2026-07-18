# Architecture

## Trust chain

```mermaid
graph TD
    RootCA["Root CA<br/>(offline, long-lived)"] -->|signs| OEMCert["OEM Signing Cert<br/>(short-lived)"]
    OEMCert -->|signs| Image["Firmware Image<br/>version + rollback_index + payload"]
    OEMCert -->|signs| Manifest["Version Manifest<br/>target hashes + metadata"]
    OEMCert -->|signs| Director["Director Metadata<br/>per-ECU target assignment"]
    OEMCert -->|signs| ImageRepo["Image Repository Metadata<br/>available targets"]
```

## Update flow

```mermaid
sequenceDiagram
    participant OEM as OEM Signing Pipeline
    participant Channel as Update Channel (untrusted)
    participant Verifier as ECU Verifier
    participant Flash as Virtual Flash (A/B slots)

    OEM->>Channel: signed image + manifest
    Channel->>Verifier: deliver (attacker can tamper here)
    Verifier->>Verifier: validate cert chain
    Verifier->>Verifier: verify image signature
    Verifier->>Verifier: check rollback index
    Verifier->>Flash: stage image in inactive slot
    Verifier->>Flash: commit rollback index
    Verifier->>Flash: flip active slot
    Note over Flash: crash/power-loss before commit<br/>leaves active slot untouched
```

## Flash memory layout

```mermaid
graph LR
    subgraph "Virtual Flash (single file, byte-addressed)"
        BL["bootloader<br/>0x0000–0x1000"]
        SA["slot_a<br/>0x1000–0x9000"]
        SB["slot_b<br/>0x9000–0x11000"]
        RC["rollback_counter<br/>0x11000–0x11010"]
        SS["slot_state<br/>0x11010–0x11020"]
        MF["manifest<br/>0x11020–0x12020"]
    end
```

## Uptane-inspired split (not spec-compliant)

BOLT's `pipeline/ota_metadata.py` borrows the director/image-repository
role separation from [Uptane](https://uptane.github.io/) at a conceptual
level: a director asserts which target an ECU should install, and an
image repository independently attests to what targets exist and their
hashes. Resolving an update requires both to agree. This is a simplified
two-role model for illustrating the idea — it does not implement Uptane's
full TUF-based role hierarchy (root/targets/snapshot/timestamp), key
thresholds, or delegation structure.
