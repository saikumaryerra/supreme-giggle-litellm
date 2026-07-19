# patches/

Escape hatch for unavoidable LiteLLM core fixes (§9.5). Normally empty —
target state is zero patches. Each patch must carry a header comment linking
the upstream PR/issue. The Dockerfile applies `*.patch` at build time and CI
fails if a patch no longer applies, forcing review on every version bump.
