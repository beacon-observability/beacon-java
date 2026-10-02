/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import static io.beacon.security.core.Values.map;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;

import io.beacon.security.core.Values;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class Component {
  final String ref;
  final String name;
  final String group;
  final String version;
  final String hash;
  final String purl;
  final String source;
  final String identityScope;
  final Set<String> locations = new LinkedHashSet<>();
  final Set<String> licenses = new LinkedHashSet<>();
  boolean loaded;
  boolean declared;

  Component(String name, String group, String version, String hash, String source) {
    this(name, group, version, hash, source, "");
  }

  Component(
      String name, String group, String version, String hash, String source, String identityScope) {
    this.name = Values.bounded(name == null || name.isEmpty() ? "unknown-component" : name, 512);
    this.group = Values.bounded(group, 512);
    this.version = Values.bounded(version, 256);
    this.hash = hash;
    this.source = source;
    this.identityScope = identityScope;
    this.purl =
        this.group.isEmpty() || this.name.equals("unknown-component")
            ? ""
            : "pkg:maven/"
                + encode(this.group)
                + "/"
                + encode(this.name)
                + (this.version.isEmpty() ? "" : "@" + encode(this.version));
    // A physical artifact retains its identity when renamed or deployed at another path.
    this.ref =
        "urn:beacon:security:component:"
            + (hash != null
                ? hash
                : digest(
                    (this.group
                            + "|"
                            + this.name
                            + "|"
                            + this.version
                            + "|"
                            + source
                            + "|"
                            + identityScope)
                        .getBytes(UTF_8)));
  }

  private Component(Component original) {
    name = original.name;
    group = original.group;
    version = original.version;
    hash = original.hash;
    source = original.source;
    identityScope = original.identityScope;
    purl = original.purl;
    ref = original.ref;
    loaded = original.loaded;
    declared = original.declared;
    locations.addAll(original.locations);
    licenses.addAll(original.licenses);
  }

  Component copy() {
    return new Component(this);
  }

  Map<String, Object> json() {
    Map<String, Object> result = map("type", "library", "bom-ref", ref, "name", name);
    if (!group.isEmpty()) {
      result.put("group", group);
    }
    if (!version.isEmpty()) {
      result.put("version", version);
    }
    if (!purl.isEmpty()) {
      result.put("purl", purl);
    }
    if (hash != null) {
      result.put("hashes", singletonList(map("alg", "SHA-256", "content", hash)));
    }
    List<Object> properties = new ArrayList<>();
    properties.add(map("name", "beacon:security:sbom:identity-source", "value", source));
    properties.add(
        map(
            "name",
            "beacon:security:sbom:deployed",
            "value",
            declared || source.equals("shaded-maven-metadata") ? "unknown" : "true"));
    if (declared) {
      properties.add(map("name", "beacon:security:sbom:declared", "value", "true"));
    }
    properties.add(map("name", "beacon:security:sbom:lifecycle", "value", "current"));
    properties.add(map("name", "beacon:security:sbom:loaded", "value", Boolean.toString(loaded)));
    if (version.isEmpty()) {
      properties.add(map("name", "beacon:security:sbom:version-status", "value", "unknown"));
    }
    result.put("properties", properties);
    List<Object> occurrences = new ArrayList<>();
    for (String location : locations) {
      occurrences.add(map("location", Values.bounded(display(location), 2048)));
    }
    if (!occurrences.isEmpty()) {
      result.put("evidence", map("occurrences", occurrences));
    }
    if (!licenses.isEmpty()) {
      List<Object> values = new ArrayList<>();
      for (String license : licenses) {
        values.add(map("license", map("name", Values.bounded(license, 512))));
      }
      result.put("licenses", values);
    }
    return result;
  }

  static String display(String location) {
    int nested = location.indexOf("!/");
    String outer = nested >= 0 ? location.substring(0, nested) : location;
    int slash = Math.max(outer.lastIndexOf('/'), outer.lastIndexOf('\\'));
    return outer.substring(slash + 1) + (nested >= 0 ? location.substring(nested) : "");
  }

  static String digest(byte[] bytes) {
    try {
      return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException(error);
    }
  }

  static String hex(byte[] bytes) {
    StringBuilder result = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) {
      result.append(Character.forDigit((value >>> 4) & 15, 16));
      result.append(Character.forDigit(value & 15, 16));
    }
    return result.toString();
  }

  private static String encode(String value) {
    try {
      return URLEncoder.encode(value, "UTF-8").replace("+", "%20");
    } catch (UnsupportedEncodingException error) {
      throw new IllegalStateException(error);
    }
  }
}
