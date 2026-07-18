# Threat Model

BOLT's attack toolkit models classes of real-world automotive OTA/boot
vulnerabilities, not hypothetical ones.

| BOLT attack | Real-world analog |
|---|---|
| `downgrade_attack` | Jeep Cherokee 2015 (Miller/Valasek): the Uconnect head unit accepted older, vulnerable firmware with no rollback protection, enabling remote code execution over cellular. |
| `strip_signature` | Multiple aftermarket ECU tuning exploits rely on flashing unsigned or weakly-checked firmware images because the bootloader never enforces signature presence, only format. |
| `mitm_channel` | Update channels delivered over plaintext or improperly validated TLS allow an on-path attacker to substitute firmware in transit; several IoT/embedded OTA systems have shipped without channel integrity checks separate from image-level signing. |
| `power_loss_sim` | Bricking-on-interrupted-flash is a known field failure mode in embedded/automotive updates; A/B partitioning (as used in Android and most automotive OTA systems) is the standard mitigation BOLT implements. |

## Trust boundaries

- **Root CA key**: assumed offline/HSM-protected in a real deployment.
  BOLT's `pki.py` generates a full root + OEM cert chain locally for
  simulation only — never treat keys or certs generated this way as
  production-grade material.
- **OEM signing certificate**: short-lived by design, so a compromised OEM
  key can be rotated (new cert issued by the root) without re-provisioning
  the root of trust on every ECU in the field. BOLT does not model
  certificate revocation (CRL/OCSP) — a compromised-but-not-expired OEM
  cert would still validate.
- **ECU verifier**: trusted compute base. If this is compromised, no
  signature scheme helps — BOLT does not model verifier-level compromise
  (e.g., glitching attacks against the boot ROM).
- **Update channel**: untrusted by design. BOLT assumes an attacker can
  read and modify all channel traffic; this is why image-level signatures,
  not channel encryption alone, are the primary defense.
- **Director vs. image repository metadata**: modeled as independently
  signed roles so that a compromise of one alone (e.g., a director service
  pushing a malicious target assignment) can't complete an update unless
  the assigned target also exists in the separately-attested image
  repository. BOLT does not implement Uptane's key thresholds or role
  delegation — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Out of scope

- Physical/hardware attacks (voltage glitching, JTAG access, side-channel
  key extraction)
- Compromise of the OEM signing infrastructure itself
- Supply-chain attacks on the payload before it reaches the signer
