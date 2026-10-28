/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import static java.util.logging.Level.WARNING;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.Settings;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.jar.Manifest;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import javax.annotation.Nullable;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

final class ArchiveScanner {
  private static final Logger logger = Logger.getLogger(ArchiveScanner.class.getName());

  interface Receiver {
    void component(Component component, String location, boolean primary);

    void imported(String location, Map<String, Object> bom);

    void incomplete(String reason);
  }

  private final Receiver receiver;
  private final ObjectMapper json = new ObjectMapper();
  private final boolean localMetadata =
      Settings.enabled("beacon.security.local-output.enabled", false);
  private final int maxNested =
      Settings.limit("beacon.security.sbom.max.archive.bytes", 64 * 1024 * 1024);
  private final int maxEntries = Settings.limit("beacon.security.sbom.max.entries", 100000);
  private final long maxBytes =
      Settings.limit("beacon.security.sbom.max.scan.bytes", 512 * 1024 * 1024);
  private int entries;
  private long bytes;

  ArchiveScanner(Receiver receiver) {
    this.receiver = receiver;
    json.getFactory()
        .setStreamReadConstraints(
            StreamReadConstraints.builder().maxNestingDepth(64).maxStringLength(65536).build());
  }

  void scan(Path path) {
    scan(path, path.toString());
  }

  void scan(Path path, String location) {
    try {
      if (Files.isDirectory(path)) {
        receiver.component(
            new Component(
                path.getFileName() == null ? "application-classes" : path.getFileName().toString(),
                "",
                "",
                null,
                "classes-directory",
                path.toString()),
            path.toString(),
            true);
        receiver.incomplete("classes_directory_metadata_partial");
        return;
      }
      if (!Files.isRegularFile(path)) {
        receiver.incomplete("unreadable_artifact");
        return;
      }
      String nested = location.substring(path.toString().length());
      scanTarget(
          path, path.toString(), nested, 0, localMetadata ? hash(path, path.toString()) : null);
    } catch (ScanLimitException ignored) {
      // The specific limit and location have already been reported. Do not resume this scan.
    } catch (Exception error) {
      receiver.incomplete("artifact_scan_" + error.getClass().getSimpleName());
    }
  }

  private void scanTarget(Path path, String location, String nested, int depth, String hash)
      throws IOException {
    if (nested.isEmpty()) {
      scanArchive(path, location, hash, depth);
      return;
    }
    if (depth >= 4) {
      receiver.incomplete("archive_depth_limit");
      return;
    }
    int next = nested.indexOf("!/", 2);
    String name = nested.substring(2, next < 0 ? nested.length() : next);
    try (ZipFile zip = new ZipFile(path.toFile())) {
      ZipEntry entry = zip.getEntry(name);
      if (entry == null || entry.isDirectory()) {
        receiver.incomplete("unreadable_artifact");
        return;
      }
      if (++entries > maxEntries) {
        receiver.incomplete("archive_entry_limit");
        return;
      }
      scanNested(
          zip, entry, location + "!/" + name, depth + 1, next < 0 ? "" : nested.substring(next));
    }
  }

  private String hash(Path path, String location) throws IOException {
    checkSize(location, bytes + Files.size(path), maxBytes, "scan_byte_limit");
    MessageDigest digest = sha256();
    try (InputStream input = Files.newInputStream(path)) {
      byte[] buffer = new byte[16384];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        consume(count, location);
        digest.update(buffer, 0, count);
      }
    }
    return Component.hex(digest.digest());
  }

  // Embedded CycloneDX JSON is checked for its BOM marker before its erased Map is retained.
  @SuppressWarnings("unchecked")
  private void scanArchive(Path path, String location, String hash, int depth) throws IOException {
    if (depth > 4) {
      receiver.incomplete("archive_depth_limit");
      return;
    }
    List<Properties> coordinates = new ArrayList<>();
    List<String> licenses = new ArrayList<>();
    String title = null;
    String version = null;
    List<Map<String, Object>> imported = new ArrayList<>();
    // Consult the central directory so unrelated entries are never inflated, even when large.
    try (ZipFile zip = new ZipFile(path.toFile())) {
      Enumeration<? extends ZipEntry> archiveEntries = zip.entries();
      while (archiveEntries.hasMoreElements()) {
        if (entries > maxEntries) {
          break;
        }
        ZipEntry entry = archiveEntries.nextElement();
        if (++entries > maxEntries) {
          receiver.incomplete("archive_entry_limit");
          break;
        }
        String name = entry.getName();
        if (entry.isDirectory()) {
          continue;
        }
        boolean nested =
            localMetadata
                && name.endsWith(".jar")
                && (name.startsWith("BOOT-INF/lib/")
                    || name.startsWith("WEB-INF/lib/")
                    || name.startsWith("WEB-INF/lib-provided/"));
        boolean metadata = name.endsWith("pom.properties") && name.contains("META-INF/maven/");
        boolean pom = localMetadata && name.endsWith("pom.xml") && name.contains("META-INF/maven/");
        boolean manifest = name.equalsIgnoreCase("META-INF/MANIFEST.MF");
        boolean bom = localMetadata && name.contains("META-INF/sbom/") && name.endsWith(".json");
        if (!(nested || metadata || pom || manifest || bom)) {
          continue;
        }
        String entryLocation = location + "!/" + name;
        if (nested) {
          if (depth >= 4) {
            receiver.incomplete("archive_depth_limit");
          } else {
            scanNested(zip, entry, entryLocation, depth + 1, "");
          }
          continue;
        }
        byte[] data;
        try (CheckedInputStream input =
            new CheckedInputStream(zip.getInputStream(entry), new CRC32())) {
          data = read(input, bom ? 1024 * 1024 : 256 * 1024, entryLocation);
          verifyEntry(entry, input, data.length);
        }
        if (metadata) {
          Properties props = new Properties();
          props.load(new ByteArrayInputStream(data));
          if (props.getProperty("artifactId") != null) {
            coordinates.add(props);
          }
        } else if (manifest) {
          Manifest values = new Manifest(new ByteArrayInputStream(data));
          title = values.getMainAttributes().getValue("Implementation-Title");
          version = values.getMainAttributes().getValue("Implementation-Version");
          if (title == null) {
            title = values.getMainAttributes().getValue("Bundle-SymbolicName");
          }
          if (version == null) {
            version = values.getMainAttributes().getValue("Bundle-Version");
          }
        } else if (pom) {
          licenses.addAll(licenses(data));
        } else {
          try {
            Map<String, Object> value = json.readValue(data, Map.class);
            if ("CycloneDX".equals(value.get("bomFormat"))) {
              imported.add(value);
            }
          } catch (IOException error) {
            receiver.incomplete("invalid_embedded_sbom");
          }
        }
      }
    }
    Properties primary = primaryCoordinates(coordinates, location);
    if (primary != null) {
      Properties p = primary;
      Component component =
          new Component(
              p.getProperty("artifactId"),
              p.getProperty("groupId"),
              p.getProperty("version"),
              hash,
              "maven-metadata",
              location);
      component.licenses.addAll(licenses);
      receiver.component(component, location, true);
      if (coordinates.size() > 1) {
        receiver.incomplete("shaded_component_identity_partial");
      }
    } else {
      Component outer =
          new Component(
              artifactName(location, version),
              "",
              version,
              hash,
              title == null ? "artifact-file" : "manifest",
              location);
      if (coordinates.isEmpty()) {
        outer.licenses.addAll(licenses);
      }
      receiver.component(outer, location, true);
      receiver.incomplete(
          coordinates.isEmpty() ? "missing_maven_identity" : "shaded_component_identity_partial");
    }
    for (Properties p : coordinates) {
      if (p != primary) {
        receiver.component(
            new Component(
                p.getProperty("artifactId"),
                p.getProperty("groupId"),
                p.getProperty("version"),
                null,
                "shaded-maven-metadata",
                location),
            location,
            false);
      }
    }
    for (Map<String, Object> bom : imported) {
      receiver.imported(location, bom);
    }
  }

  @Nullable
  private static Properties primaryCoordinates(List<Properties> coordinates, String location) {
    if (coordinates.size() == 1) {
      return coordinates.get(0);
    }
    String file = fileName(location);
    Properties match = null;
    for (Properties candidate : coordinates) {
      String artifact = candidate.getProperty("artifactId", "");
      String version = candidate.getProperty("version", "");
      if (!artifact.isEmpty()
          && !version.isEmpty()
          && file.equals(artifact + "-" + version + ".jar")) {
        if (match != null) {
          return null;
        }
        match = candidate;
      }
    }
    return match;
  }

  private static String fileName(String location) {
    int slash = Math.max(location.lastIndexOf('/'), location.lastIndexOf('\\'));
    return location.substring(slash + 1);
  }

  private static String artifactName(String location, String version) {
    String file = fileName(location);
    String name = file.endsWith(".jar") ? file.substring(0, file.length() - 4) : file;
    if (version != null
        && !version.isEmpty()
        && name.endsWith("-" + version)
        && name.length() > version.length() + 1) {
      return name.substring(0, name.length() - version.length() - 1);
    }
    return name;
  }

  private void scanNested(ZipFile zip, ZipEntry entry, String location, int depth, String nested)
      throws IOException {
    checkSize(location, entry.getSize(), maxNested, "archive_byte_limit");
    checkSize(location, bytes + entry.getSize(), maxBytes, "scan_byte_limit");
    // Stage only selected nested archives, bounding heap use independently of the archive size.
    Path temporary = Files.createTempFile("beacon-sbom-", ".jar");
    try {
      MessageDigest digest = localMetadata ? sha256() : null;
      try (CheckedInputStream input =
              new CheckedInputStream(zip.getInputStream(entry), new CRC32());
          OutputStream output = Files.newOutputStream(temporary)) {
        byte[] buffer = new byte[8192];
        long size = 0;
        int count;
        while ((count = input.read(buffer)) >= 0) {
          size += count;
          consume(count, location);
          checkSize(location, size, maxNested, "archive_byte_limit");
          output.write(buffer, 0, count);
          if (digest != null) {
            digest.update(buffer, 0, count);
          }
        }
        verifyEntry(entry, input, size);
      }
      scanTarget(
          temporary,
          location,
          nested,
          depth,
          digest == null ? null : Component.hex(digest.digest()));
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException(error);
    }
  }

  private static void verifyEntry(ZipEntry entry, CheckedInputStream input, long size)
      throws IOException {
    // Unlike ZipInputStream, ZipFile entry streams do not validate the size or CRC themselves.
    if (size != entry.getSize() || input.getChecksum().getValue() != entry.getCrc()) {
      throw new ZipException("Invalid ZIP entry size or CRC");
    }
  }

  private byte[] read(InputStream input, int limit, String location) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int count;
    while ((count = input.read(buffer)) >= 0) {
      consume(count, location);
      checkSize(location, output.size() + (long) count, limit, "metadata_byte_limit");
      output.write(buffer, 0, count);
    }
    return output.toByteArray();
  }

  private void consume(int count, String location) throws IOException {
    bytes += count;
    checkSize(location, bytes, maxBytes, "scan_byte_limit");
  }

  private void checkSize(String location, long size, long limit, String reason) throws IOException {
    if (size > limit) {
      limit(reason, location, limit, size);
    }
  }

  private void limit(String reason, String location, long limit, long observed) throws IOException {
    receiver.incomplete(reason);
    logger.log(
        WARNING,
        "[BeaconSecurity] SBOM scan limit reached: reason={0}, location={1}, limit_bytes={2}, observed_bytes={3}",
        new Object[] {reason, location, Long.toString(limit), Long.toString(observed)});
    throw new ScanLimitException(reason);
  }

  private static final class ScanLimitException extends IOException {
    ScanLimitException(String reason) {
      super(reason);
    }
  }

  private List<String> licenses(byte[] data) {
    List<String> result = new ArrayList<>();
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      Document document = factory.newDocumentBuilder().parse(new ByteArrayInputStream(data));
      NodeList nodes = document.getElementsByTagName("license");
      for (int i = 0; i < Math.min(nodes.getLength(), 16); i++) {
        NodeList children = nodes.item(i).getChildNodes();
        for (int j = 0; j < children.getLength(); j++) {
          if (children.item(j).getNodeName().equals("name")) {
            result.add(children.item(j).getTextContent().trim());
          }
        }
      }
    } catch (Exception ignored) {
      receiver.incomplete("license_metadata_unreadable");
    }
    return result;
  }
}
