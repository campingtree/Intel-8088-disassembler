# Intel-8088-disassembler

## Peculiarities:
* Disassembles only the core commands.
* List of disassemblable commands can be found in [core.inc](/core.inc) FORMAT struct table.
* Disassembles full .exe files (*not .com*)

## To run:
`disass.exe input_program.exe output.asm`

## How to dissasemble new commands:
* Simply add the format for your desired command in [core.inc](/core.inc) FORMAT struct table. Then in [disass.asm](/disass.asm), write the according parsing procedure.

## Notes: