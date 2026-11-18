# AEGIS — Risk Scoring Methodology

AEGIS scores every attack path with a **transparent, additive model**. Every score is stored with the value,
weight, points and reason for each factor, and the points always sum to the score. Administrators can change every
parameter. The implementation is in `backend/app/risk_engine/` and the parameters are stored in the `settings`
table under `risk_config`.

A score ranks *what the collected data supports*. It is not a probability of compromise and it does not mean the path
has been exploited.

## 1. Path score

```
score = 100 × Σ wᵢ·fᵢ / Σ wᵢ          every factor fᵢ ∈ [0, 1]; weights are normalised to sum to 1
```

| Factor | Default weight | How it is computed | Rationale |
|---|---|---|---|
| **Destination privilege** | 0.30 | Highest privilege among the target's tier-0 categories (table below). Members inherit their groups' categories, all of them, computed to a fixpoint. | Reaching Domain Admins is worse than reaching Print Operators |
| **Exploitability** | 0.15 | 1.0 if every step is unconditional. `conditional_factor` (0.7) if any step needs validation. 1.0 once an analyst validates it. | Conditional steps (sessions, delegation, shadow credentials) may not hold |
| **Proximity** | 0.15 | `hop_decay^(hops − 1)`, with hop_decay 0.85: 1 hop → 1.00, 2 → 0.85, 3 → 0.72, 5 → 0.52, 8 → 0.32 | Short paths are easier, quieter and more likely to be found by attackers |
| **Relationship severity** | 0.10 | Mean of the steps' rule severities (`graph_engine/rules.py`, e.g. MemberOf 0.6, WriteDacl 0.95) | Some relationships are more dangerous than others |
| **Confidence** | 0.10 | Product of the steps' evidence confidences: ACL 0.95, membership 1.0, session 0.7, registry session 0.6, inventory as declared | Point-in-time or indirect evidence is less certain |
| **Exposure** | 0.08 | `ln(1 + n) / ln(1 + exposure_saturation)`, where n is the number of identities whose shortest path ends at the same target. Saturation is 100. | A target reachable by many identities is more exposed |
| **Alternatives** | 0.04 | `(routes − 1) / (alternatives_saturation − 1)` for the source identity, capped at 1, with saturation 5 | Identities with several routes are harder to remediate |
| **Evidence completeness** | 0.05 | `1 − placeholder objects on the path / objects on the path` | Paths through objects missing from the collection are less certain |
| **Asset criticality** | 0.03 | Highest administrator-assigned business criticality (0–1) of any object on the path. 0 if none is configured. | Lets the organisation weight what matters to it |

### Destination privilege by tier-0 category (`category_privilege`)

| Category | Value | Category | Value |
|---|---|---|---|
| domain, domain_controllers, domain_admins, enterprise_admins, administrators, dcsync, builtin_accounts (Administrator, krbtgt) | 1.0 | schema_admins, key_admins | 0.9 |
| operators (Account, Server, Print, Backup) | 0.8 | custom (administrator-designated) | 0.8 |
| hint (imported high-value flag, only if trusted) | 0.6 | target without a category | 0.7 |

## 2. Severity bands

| Severity | Score |
|---|---|
| Critical | ≥ 80 |
| High | ≥ 60 |
| Medium | ≥ 40 |
| Low | < 40 |

**Conditional cap:** an unvalidated *conditional attack path* can be at most **High**
(`conditional_max_severity`). This is the main safeguard against labelling everything Critical. A path becomes
Critical only when its score earns it *and* nothing about it still needs validation.

**Validation:** when an analyst confirms a path in an authorised test, it becomes a *validated security exposure*.
It is rescored with exploitability 1.0, using the weights stored with the path so the result stays comparable, and
the cap no longer applies. The validation note, the analyst and the time are recorded.

## 3. Worked example (corp-small sample data, default configuration)

`IVAN -MemberOf-> IT-ADMINS -WriteDacl-> DOMAIN ADMINS` (2 hops, unconditional)

| Factor | Value | Weight | Points | Reason |
|---|---|---|---|---|
| Destination privilege | 1.000 | 0.30 | 30.00 | DOMAIN ADMINS is tier-0 (domain admins) |
| Exploitability | 1.000 | 0.15 | 15.00 | every step is unconditionally abusable |
| Proximity | 0.850 | 0.15 | 12.75 | 2 steps |
| Relationship severity | 0.775 | 0.10 | 7.75 | mean of MemberOf 0.60 and WriteDacl 0.95 |
| Confidence | 0.950 | 0.10 | 9.50 | membership 1.0 × ACL 0.95 |
| Exposure | 0.238 | 0.08 | 1.90 | 2 identities reach DOMAIN ADMINS: ln 3 / ln 101 |
| Alternatives | 0.000 | 0.04 | 0.00 | 1 route from IVAN |
| Evidence completeness | 1.000 | 0.05 | 5.00 | every object was collected |
| Asset criticality | 0.000 | 0.03 | 0.00 | none configured |
| **Score** | | | **81.90** | **Critical** |

The test `test_documented_example_ivan_scores_exactly` keeps this example correct.
Across the corp-small dataset the model produces 2 Critical paths (the two unconditional routes to Domain Admins) and
6 High paths. Every conditional path is High: the session paths, RBCD to the domain controller, and the GPO chain.

## 4. Environment risk (dashboard and simulation comparisons)

```
environment = 0.5 × worst path score
            + 0.3 × exposure mass,  mass    = 100 × min(1, Σ over exposed identities of (worst path score / 100)
                                                       / environment_mass_saturation)       saturation = 10
            + 0.2 × breadth,        breadth = 100 × min(1, exposed identities / all starting identities / 0.05)
```
* The **worst path** captures the immediate danger.
* The **exposure mass** grows with both the number of exposed identities and how bad their paths are. Ten identities
  that each have a 100-point path saturate it.
* **Breadth** reaches its maximum once 5% of identities can reach tier-0.

corp-small scores **74.88**: 0.5 × 81.90 + 0.3 × 46.43 + 0.2 × 100. The components are stored with each analysis.

**Monotonicity requirement.** Remediating something must never make the environment score go up, or remediation
simulations would be misleading. An earlier version used the *mean* of exposed identities' worst scores. The
simulation tests caught that securing two low-scoring identities raised the mean, and with it the overall score,
from 84.17 to 84.97. Every component is now a maximum, a capped sum or a capped count, all of which can only fall
when relationships or identities are removed. The test
`test_environment_risk_never_increases_when_any_relationship_is_removed` removes each traversable relationship of
corp-small in turn and checks this property.

## 5. Configuration reference (`risk_config`)

| Key | Default | Constraint |
|---|---|---|
| `weights` | table in §1 | exactly the 9 factors, non-negative, not all zero |
| `category_privilege` | table in §1 | values in [0, 1] |
| `default_privilege` | 0.7 | [0, 1] |
| `hop_decay` | 0.85 | (0, 1] |
| `conditional_factor` | 0.7 | [0, 1] |
| `exposure_saturation` | 100 | ≥ 1 |
| `alternatives_saturation` | 5 | ≥ 2 |
| `environment_mass_saturation` | 10 | > 0 |
| `bands` | Critical 80, High 60, Medium 40 | 100 ≥ Critical > High > Medium > 0 |
| `conditional_max_severity` | High | one of Critical, High, Medium, Low |
| `asset_criticality` | {} | object_id → [0, 1] |

Each analysis stores the normalised weights it used (`summary.risk_weights`), so a later change of weights never
silently changes the meaning of old results.
