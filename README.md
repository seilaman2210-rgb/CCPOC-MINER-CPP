# 🌱 CCPoC Plotter, Lets mine! :3

![Intel Arc](https://img.shields.io/badge/Intel%20Arc-Supported-0068B5?style=for-the-badge&logo=intel&logoColor=white)

Plotter with Intel Arc Support (tested with ARC a310).
More GPUs support soon (next will be NVIDIA)

### Status:

> *light-node.cpp » pre-alpha, v0.01*
> *Plotter.cpp » Possibly some, Future changed should only include New devices supports! v1.0.0*

### What is the light-node supposed to do?

> Sync blocks (Full Chain or sliding window only, 8192 blocks), verify ZKP proofs for sliding window, be a Full Api endpoint (local wallet.py Will talk with light node via TCP RAW, but why? because then your wallet can see the whole history with explorer, stay synced with Full node (light node syncs) and others

> maybe we can add them as actual nodes on future (public url) but with prunning.
