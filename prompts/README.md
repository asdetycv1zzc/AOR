# Prompt Bundles

Global and role prompts are immutable, versioned inputs with explicit authority and trust labels. Prompt rules guide behavior but never grant capabilities.

The production baseline is stored in `v1.0.0/catalog.json`. Runtime callers load it through `prompts.LoadBaseline`, which rejects unknown fields and computes the content-bound `PromptBundle` digest recorded with every model call.
