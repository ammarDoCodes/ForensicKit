# Third-party notices

The ForensicKit core application uses Python's standard library only. This
source repository does not include a Python interpreter. A separately built
Windows desktop package bundles CPython 3.12 and includes its upstream
`LICENSE.txt` at `runtime/LICENSE.txt`; confirm that license is present in
each generated package.

The native desktop launcher uses the Windows .NET Framework WinForms and
System.Drawing assemblies supplied by Microsoft Windows. No third-party
managed or JavaScript dependency is bundled. The workbench uses no external
font, script, image, analytics, or network resource.

Raw EVTX support is optional and is not part of the default Windows package.
`python-evtx==0.8.1` is documented as a separate optional dependency for a
developer-managed Python environment. It is not included in the package, and
the package does not claim full binary validation. Current status:
EVTX PARTIALLY VALIDATED — pending approved Windows Security and PowerShell binary fixtures.

No private keys, signing certificates, credentials, or provider secrets are
included. This executable is unsigned.
