# z80cmp
A z80 disassambler aimed at easing comparison of variations of the same program


## Background
When comparing binaries of different versions of the same program, analyzing differences can be challenging. In many cases, new instructions are inserted, causing all subsequent addresses in the binary to shift. This makes direct binary comparisons produce numerous spurious differences that are not meaningful. Similarly, disassembling these binaries and comparing the resulting code with standard diff tools also yields misleading results, as the automatically generated labels depend on specific addresses and do not align across versions.

To address this, z80cmp.py generates disassembly with consistent labels shared across multiple files. By harmonizing the labels and formatting the disassembly, this utility allows meaningful diffs that highlight only actual changes in the code logic or structure, ignoring irrelevant differences like address shifts.

## Features
- Generates disassembly with shared labels for easy comparison.
- Facilitates meaningful diffs by eliminating spurious differences caused by address shifts.
- Supports pairwise comparisons of multiple binaries.
- Aligns output rows for easier comparison


```text
usage: z80cmp.py [-h] [--suffix SUFFIX] [--pairwise] [--align] filenames [filenames ...]

Process binary files to generate comparable disassembly outputs.

Positional Arguments:
  filenames        List of binaries to process.

Options:
  -h, --help       Show this help message and exit.
  --suffix SUFFIX  Custom suffix for label generation. Defaults to stems of the other files the file is being compared to.
  --pairwise       Enable pairwise comparisons of binaries.
  --align          Align rows in the outputs so that matching code is located at the same line in the file.

```
# Todo
- data/code separation


## Show Your Support

<a href='https://ko-fi.com/R6R31177HE' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a> if you want to support further development!

