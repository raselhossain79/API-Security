# API6:2023 — Unrestricted Access to Sensitive Business Flows

Note series covering OWASP API Security Top 10 2023 — API6: Unrestricted Access to Sensitive Business Flows. Companion series to the existing API4 (Unrestricted Resource Consumption), API3 (BOPLA/Mass Assignment), API5 (BFLA), and REST API testing methodology series.

## File index

| File | Description |
|---|---|
| [01-overview-and-concept.md](01-overview-and-concept.md) | Core concept, mechanism, why the API allows it, distinction from API4/API1/API5, series scope, and an honest statement on WAF/Gateway relevance for this vulnerability class |
| [02-real-world-scenarios.md](02-real-world-scenarios.md) | Six scenarios broken down step by step: ticket/inventory scalping, referral reward farming, gift card/coupon stacking, account enumeration at scale, payment flow step-skip bypass, voting/rating manipulation |
| [03-detection-and-testing-methodology.md](03-detection-and-testing-methodology.md) | Recon checklist, automation-control probing methodology, PortSwigger lab mapping (Apprentice → Practitioner → Expert), crAPI supplementary mapping, WAF/Gateway detection and bypass |
| [04-workflow-step-skipping.md](04-workflow-step-skipping.md) | Full technique breakdown for multi-step flow bypass: raw omission, client-trusted state flags, amount tampering, step reordering, cross-flow identifier reuse |
| [05-turbo-intruder-business-flow-testing.md](05-turbo-intruder-business-flow-testing.md) | Turbo Intruder script breakdowns, flag by flag, for rate-limit discovery, coupon enumeration, single-use race conditions, referral farming simulation, and step-skip regression testing |
| [06-cheatsheet.md](06-cheatsheet.md) | Condensed quick-reference: recognition checklist, testing checklist, scenario → root-cause map, Turbo Intruder config table, PortSwigger lab order, report-writing reminder |

## Series conventions

- Mechanism-first explanations — every vulnerability is explained by *why the API allows it*, not just *how to exploit it*.
- Every real-world example is broken down step by step, naming the specific business rule violated.
- PortSwigger labs are mapped in Apprentice → Practitioner → Expert order with honest disclosure of where PortSwigger's lab format cannot fully represent this vulnerability class (single-actor logic flaws vs. automation-at-scale abuse).
- crAPI is used as supplementary practice specifically to fill that automation/scale gap.
- Every file includes a dedicated WAF/API Gateway section — for this vulnerability class specifically, that section explains why signature-based detection doesn't apply and instead covers behavioral/velocity detection and realistic bypass considerations.
- Full English only, no informal language, GitHub-ready Markdown.

## Suggested reading order

1. Start with `01` for the concept and mental model.
2. Read `02` for concrete scenarios before touching any tooling.
3. Use `03` to structure actual testing and lab practice.
4. Go deep on `04` if the target has any multi-step process (checkout, onboarding, KYC).
5. Use `05` when ready to script real automation tests.
6. Keep `06` open as a reference during live testing or report writing.
