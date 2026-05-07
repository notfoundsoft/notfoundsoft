```
              _    __                       _
  _ __   ___ | |_ / _| ___  _   _ _ __   __| |
 | '_ \ / _ \| __| |_ / _ \| | | | '_ \ / _` |
 | | | | (_) | |_|  _| (_) | |_| | | | | (_| |
 |_| |_|\___/ \__|_|  \___/ \__,_|_| |_|\__,_|
```

> `HTTP/1.1 404` — not the binary you're looking for.
>
> _compiled with `-Wall -Werror -fstack-protector-all -fno-bullshit`_

<!-- flag{notfound_was_here} -->

---

## `$ whoami`

Reverse engineer. Malware analyst. Exploit analyst.
Userland to ring 0, on `x86_64` and `ARM/AArch64`.

```
Name:       notfound
State:      R (reversing)
TracerPid:  0
SigCgt:     SIGSEGV SIGBUS SIGILL  (caught, analyzed, filed)
```

I read binaries the way other people read novels. Slower. Less linear. More footnotes. The bug is always in the assumption — mine, the developer's, or the compiler's.

Outputs ship to defenders: detections, mitigations, advisories, hardening notes.

---

## `$ cat focus.txt`

- Static and dynamic reverse engineering of Linux binaries
- Malware triage, unpacking, and loader analysis
- Vulnerability root-cause and exploitability assessment
- Crash triage and memory corruption forensics
- Detection engineering and signature development
- Mitigation review and bypass research, from the defender's chair

---

## `$ ./re`

> Files lie. Disassembly doesn't.

- ELF internals: headers, segments, sections, relocations, dynamic linking, GOT/PLT
- Static analysis: Ghidra, IDA, Binary Ninja, radare2, rizin
- Dynamic analysis: GDB, LLDB, pwndbg, gef
- Tracing and instrumentation: `strace`, `ltrace`, QEMU user-mode
- Binutils: `objdump`, `readelf`, `nm`, `file`
- Cross-arch reading: `x86_64`, `ARM`, `AArch64`
- Anti-analysis: packers, encoded loaders, control-flow flattening, anti-debug

---

## `$ ./triage`

> Bin came in. Truth came out.

- Linux ELF samples: implants, droppers, miners, ransomware, rootkits
- Static unpacking and configuration extraction
- Sandboxed dynamic execution under QEMU and isolated VMs
- Behavioral profiling: persistence, C2 patterns, syscall fingerprints, capability inventory
- YARA for sample families and loader stages
- Sigma for host telemetry and EDR coverage

A teaser — flag any ELF marked `ET_DYN`:

```yara
import "elf"

rule elf_position_independent {
  condition:
    uint32(0) == 0x464c457f and elf.type == elf.ET_DYN
}
```

---

## `$ ./crash-explorer`

> Every crash is a question. Exploitability is the answer.

- Memory corruption root-cause: stack, heap, UAF, type confusion, OOB
- Primitives: arbitrary read, arbitrary write, control-flow hijack
- Triage of crashes and fuzzer findings
- Mitigation review: NX, ASLR, PIE, RELRO, stack canaries, CFI, FORTIFY, SMEP/SMAP, KPTI, PAC/BTI
- Public CVE study, patch diffing, primitive reconstruction

---

## `$ uname -a`

| Domain        | Targets                                                  |
|---------------|----------------------------------------------------------|
| Architectures | `x86_64`, `ARM`, `AArch64`                               |
| OS            | Linux userland, Linux kernel, embedded Linux             |
| Formats       | ELF executables, shared objects, kernel modules, cores   |
| Runtimes      | glibc, musl, BusyBox userlands                           |

---

## `$ which $TOOLS`

```
disasm     ghidra  ida  binja  r2  rizin
debug      gdb  lldb  pwndbg  gef
emulate    qemu (user + system)
trace      strace  ltrace
binutils   objdump  readelf  nm  file
detect     yara  sigma
write      c  python  asm (x86_64, arm, aarch64)
```

---

## `$ tail -f notes.md`

- Loader behavior and early execution in modern Linux ELF malware
- Detection coverage for `AArch64` Linux samples — still thin in the wild
- Heap primitive characterization in glibc and musl
- Crash-to-exploitability heuristics for fuzzer findings
- Mitigation effectiveness against realistic attacker primitives

---

## `$ cat ETHICS`

- Lab only. Targets are mine or the engagement's.
- Detections over demos. Boring writeups beat flashy videos.
- Coordinated disclosure. Vendors first, the world second.
- Public artifacts redact what helps offense more than defense.
- Knowledge is fine. Operations are not.

---

## `$ ls -la ~/repos/`

- Annotated disassembly and reversing notes
- Malware writeups and IOC sets
- YARA + Sigma collections
- CVE root-cause studies and patch diffs
- Tooling for triage, unpacking, and inspection
- Lab scaffolding for QEMU multi-arch analysis

---

## `$ cat ACKNOWLEDGEMENTS`

Inspired by Phrack 49, Aleph One, and every "yes, but why does it crash" moment.

---

<!-- if you're reading this, you're already deeper than most -->

## `$ finger notfound`

- web   <https://notfound.github.io>
- blog  <https://notfound.github.io>
- mail  <notfoundsoft@gmail.com>
- pgp   `C80C 3C16 6DEF C9D7 8C03  23BE AA18 BCA7 0A41 0258` ([pubkey.asc](pubkey.asc))

```
$ exit 0  # connection terminated. resource still 404.
```
