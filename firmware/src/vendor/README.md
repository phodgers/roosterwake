# Vendored third-party code

## jsmn

- **Files**: `jsmn.h`, `LICENSE.jsmn`
- **Upstream**: <https://github.com/zserge/jsmn>
- **Revision**: `25647e692c7906b96ffd2b05ca54c097948e879c` (2021-10-14)
- **Licence**: MIT (see `LICENSE.jsmn`), compatible with this firmware's MIT licence
- **Modifications**: none. The file is byte-identical to upstream.

Vendored rather than fetched at build time because a device firmware build should not depend
on a network, and because a single 471-line header is easier to audit than a dependency
manifest. `jsmn.c` is ours: it is the one translation unit that instantiates jsmn's inline
implementation, which `proto/json.h` suppresses everywhere else with `JSMN_HEADER`.

jsmn was chosen over the alternatives for one property: it allocates nothing. It writes tokens
into a caller-supplied array and never touches the heap, which is what makes it safe to parse
attacker-influenced input on a device with no memory to spare and no way to report an
allocation failure to anybody.

To update: replace `jsmn.h` from upstream, record the new revision here, and run the host test
suite — `proto/json.c` depends on jsmn's token layout, and the `rw_json_skip()` walk in
particular relies on tokens being emitted in document order.
