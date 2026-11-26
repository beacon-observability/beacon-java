# Security SIEM migration

The Agent no longer exports a SIEM envelope. See [Security log output](LOG-OUTPUT.md)
for the current direct-Body binding, metadata placement, local file format, and
receiver migration from Beacon Java 1.5.0. A fifteen-field SIEM projection may still
be applied by an explicitly configured downstream pipeline using the shared
specification; it is not the Agent wire format.
