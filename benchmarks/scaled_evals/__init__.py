"""Full public-dataset benchmarking layer for aginiti-redteam.

Separate from the 25-record Faker fixture in ``benchmarks/dev_fixtures/agents`` /
``benchmarks/dev_fixtures/datasets`` (which serves ``tests/``). This layer runs attacks
against a real public dataset (HealthCareMagic-1k) to measure attack
effectiveness with numbers comparable to the IKEA paper. See
``docs/benchmarking.md``.
"""
