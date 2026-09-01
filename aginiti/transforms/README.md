# aginiti/transforms — composable prompt-encoding pipeline

| Module | What it does |
|---|---|
| `converters.py` | A composable prompt-transformation pipeline — `Converter.convert()` (forward transform) + `decode_hint()` (natural-language instruction telling the TARGET how to reverse it, since a real chat model has to read and act on the encoded prompt, not just have it fuzzed). `ConverterPipeline` composes several converters and produces one compound decode hint listing undo steps in the correct order. Inspired by PyRIT's `PromptConverter` interface shape and garak's `encoding` probe's list of encoding families — neither copied verbatim; every encoding is implemented fresh against Python's stdlib or a small literal lookup table. See the module's own docstring for the full list of encodings and attribution. |

Deliberately not wired into any operator's default behavior directly —
`aginiti/operators/encoding_variants.py` is the operator-generation layer
that turns this pipeline into a family of `Operator` instances.
