# CruftIdentifier
Batch tool that receives a collection of target directories as input, then identifies any files or directories that match a pattern defined in the provided patterns file.

Patterns are specified in a text file that should be located alongside the executable. The text file shall have the name SuspiciousStrings.txt

Matching structure: <text_to_match> <d|f> <t[n{1}]|f> [p|{s}]
1. Text_to_match - Text pattern to match against.
2. d|f - Directory or file.
3. t[n]|f - Report parent directory. If t, specify a number above 0 for how many parent directories up you wish to report. Default is 1.
4 (opt). p|s. Suffix is the default. Not relevant if a complete match is desired.
