/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import io.beacon.security.core.Settings;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ArtifactCache implements ArchiveScanner.Receiver {
  private final List<Entry> entries = new ArrayList<>();
  private final List<Declaration> declarations = new ArrayList<>();
  private final Set<String> reasons = new LinkedHashSet<>();
  final String fingerprint;
  final long scannedAt = System.currentTimeMillis();

  ArtifactCache(Path path, String fingerprint) {
    this.fingerprint = fingerprint;
    new ArchiveScanner(this).scan(path);
  }

  static String fingerprint(Path path) {
    try {
      BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
      return attrs.size() + "|" + attrs.lastModifiedTime() + "|" + attrs.fileKey();
    } catch (Exception error) {
      return "unreadable";
    }
  }

  boolean reusable(String current) {
    return fingerprint.equals(current)
        && !fingerprint.equals("unreadable")
        && reasons.stream()
            .noneMatch(
                reason ->
                    reason.startsWith("artifact_scan_") || reason.equals("unreadable_artifact"))
        && System.currentTimeMillis() - scannedAt
            < Settings.limit("beacon.security.sbom.cache.seconds", 300) * 1000L;
  }

  void replay(ArchiveScanner.Receiver receiver) {
    for (Entry entry : entries)
      receiver.component(entry.component.copy(), entry.location, entry.primary);
    for (Declaration declaration : declarations)
      receiver.imported(declaration.location, declaration.bom);
    for (String reason : reasons) receiver.incomplete(reason);
  }

  @Override
  public void component(Component component, String location, boolean primary) {
    if (entries.size() < Settings.limit("beacon.security.sbom.max.components", 10000))
      entries.add(new Entry(component, location, primary));
    else incomplete("component_count_limit");
  }

  @Override
  public void imported(String location, Map<String, Object> bom) {
    if (declarations.size() < 64) declarations.add(new Declaration(location, bom));
    else incomplete("embedded_sbom_limit");
  }

  @Override
  public void incomplete(String reason) {
    if (reasons.size() < 128) reasons.add(reason);
  }

  private static final class Entry {
    final Component component;
    final String location;
    final boolean primary;

    Entry(Component component, String location, boolean primary) {
      this.component = component;
      this.location = location;
      this.primary = primary;
    }
  }

  private static final class Declaration {
    final String location;
    final Map<String, Object> bom;

    Declaration(String location, Map<String, Object> bom) {
      this.location = location;
      this.bom = bom;
    }
  }
}
