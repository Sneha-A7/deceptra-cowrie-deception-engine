# Deceptra — Cowrie SSH Honeypot Deception Enhancement

Deceptra is a cybersecurity research and engineering project focused on enhancing the deception capabilities of the Cowrie SSH honeypot through more consistent Linux environment simulation and attack-interaction analysis.

## Project Overview

SSH honeypots are used to observe and analyse attacker interactions. The realism and consistency of the simulated environment can influence the quality of these interactions and the data collected.

This project explores improvements to Cowrie's simulated Linux environment, particularly command responses and filesystem behaviour.

## Research Focus

The primary research focus is:

**Inconsistent simulated Linux command responses and filesystem behaviour in SSH honeypots.**

The project aims to investigate whether a more consistent simulated Linux environment can improve deception quality and provide more useful attack-interaction observations.

## Current Components

- Cowrie-based SSH honeypot configuration.
- Debian 12 environment profile.
- Custom simulated filesystem components.
- Command-response consistency checker.
- Attack-interaction analysis scripts.
- Dashboard application for visualising analysis.

## Technology

- Cowrie SSH Honeypot
- Python
- Linux / Ubuntu
- JSON
- Streamlit or Python dashboard components (implementation to be verified)

## Repository Structure

```text
.
├── analyzer.py
├── analyzer_v1.py
├── analyzer_v2.py
├── analyzer_v2_final.py
└── deception_project/
    ├── check_consistency.py
    ├── dashboard/
    ├── honeyfs/
    ├── profiles/
    ├── results/
    └── tests/
```

## Research and Evaluation

The intended evaluation compares the original Cowrie environment with the enhanced environment using controlled command interactions and consistency checks.

Evaluation results will be documented as experiments are completed.

## Project Status

Work in progress.

The current repository contains the initial implementation and analysis components. Further integration, testing, documentation and comparative evaluation remain part of the ongoing work.

## Disclaimer

This project is intended for authorised cybersecurity research and educational use. Honeypot deployments should be isolated and configured responsibly.

## Acknowledgements

This project builds upon the open-source Cowrie SSH honeypot.

Original project: https://github.com/cowrie/cowrie
