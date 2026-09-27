# JIP novelty and related-work check (2026-09-27)

This is a focused prior-art check, not a claim that the literature search is
exhaustive. Only primary publication/standards pages were used.

| Existing work | Established idea | Consequence for this paper |
| --- | --- | --- |
| Liu and Scheffler, *Privacy-preserving Age Verification based on Improved Verifiable Credentials Framework*, ConPro 2025 work in progress, https://www.ieee-security.org/TC/SPW2025/ConPro/papers/liu-conpro25.pdf | The age-check motivation explicitly notes that a birth date is excessive when an over-18 result suffices and proposes a result-only privacy-preserving VC framework. | Do **not** claim that DOB-to-over-18 minimization or predicate-only verification is new. Their proposal is not this paper's Keycloak/OpenFGA negative-control evaluation. |
| Paquin, Policharla, and Zaverucha, *Crescent: Stronger Privacy for Existing Credentials*, IACR ePrint 2024, https://www.microsoft.com/en-us/research/publication/crescent-stronger-privacy-for-existing-credentials/ | Converts existing JWT/mDL credentials into selective-disclosure and unlinkable proofs, with an online age-verification demo. | Current signed predicate and cached C are weaker privacy mechanisms; do not claim unlinkability or state of the art. |
| OASIS, *XACML 3.0*, https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-en.html | Separates a policy decision point from an enforcement point. | Pre-issuance PEP is an established architectural pattern, not protocol novelty. |
| Wang, Ko, and Mickens, *Riverbed*, NSDI 2019, https://www.usenix.org/conference/nsdi19/presentation/wang-frank | End-to-end privacy-policy enforcement for distributed services, with stronger attested enforcement. | Do not claim the general idea of enforcing privacy policy across a service boundary is new. |

Potential contribution: a small, reproducible, version-pinned **integration
case study** that shows how three existing OSS evidence routes fail or satisfy
the same frozen invariants, reproduces the decision/enforcement split as a
negative control, and checks a narrow PEP intervention. The new local O_live
supplement closes only the stored-flag semantic gap at a synthetic boundary;
it does not by itself create a novel age-verification method. This is a
reasonable Technical Note framing but **not an acceptance prediction**.

JIP's current landing page says nonmembers may submit, while its linked 2017
author rules still say authors should be IPSJ members. The contradiction
should be clarified with the editorial office before final submission if the
portal requires a member ID: https://www.ipsj.or.jp/english/jip/index.html and
https://www.ipsj.or.jp/english/jip/submit/ronbun_e_prms.html . IEEE membership
is not IPSJ membership.
