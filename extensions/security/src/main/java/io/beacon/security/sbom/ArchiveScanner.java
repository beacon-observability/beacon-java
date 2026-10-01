/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.Settings;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

final class ArchiveScanner {
  interface Receiver {
    void component(Component component, String location, boolean primary);

    void imported(String location, Map<String, Object> bom);

    void incomplete(String reason);
  }

  private final Receiver receiver;
  private final ObjectMapper json = new ObjectMapper();
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
      String hash = hash(path);
      try (InputStream input = Files.newInputStream(path)) {
        scanArchive(input, path.toString(), hash, 0);
      }
    } catch (Exception error) {
      receiver.incomplete("artifact_scan_" + error.getClass().getSimpleName());
    }
  }

  private String hash(Path path) throws Exception {
    if (Files.size(path) > maxBytes - bytes) {
      receiver.incomplete("scan_byte_limit");
      return null;
    }
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream input = Files.newInputStream(path)) {
      byte[] buffer = new byte[16384];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        bytes += count;
        if (bytes > maxBytes) throw new IOException("scan limit");
        digest.update(buffer, 0, count);
      }
    }
    return Component.hex(digest.digest());
  }

  // Embedded CycloneDX JSON is checked for its BOM marker before its erased Map is retained.
  @SuppressWarnings("unchecked")
  private void scanArchive(InputStream input, String location, String hash, int depth)
      throws IOException {
    if (depth > 4) {
      receiver.incomplete("archive_depth_limit");
      return;
    }
    List<Properties> coordinates = new ArrayList<>();
    List<String> licenses = new ArrayList<>();
    String title = null;
    String version = null;
    List<Map<String, Object>> imported = new ArrayList<>();
    try (ZipInputStream zip = new ZipInputStream(input)) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        if (++entries > maxEntries) {
          receiver.incomplete("archive_entry_limit");
          break;
        }
        String name = entry.getName();
        if (entry.isDirectory()) continue;
        boolean nested =
            name.endsWith(".jar")
                && (name.startsWith("BOOT-INF/lib/")
                    || name.startsWith("WEB-INF/lib/")
                    || name.startsWith("WEB-INF/lib-provided/"));
        boolean metadata = name.endsWith("pom.properties") && name.contains("META-INF/maven/");
        boolean pom = name.endsWith("pom.xml") && name.contains("META-INF/maven/");
        boolean manifest = name.equalsIgnoreCase("META-INF/MANIFEST.MF");
        boolean bom = name.contains("META-INF/sbom/") && name.endsWith(".json");
        if (!(nested || metadata || pom || manifest || bom)) {
          byte[] buffer = new byte[8192];
          long skipped = 0;
          int count;
          while ((count = zip.read(buffer)) >= 0) {
            bytes += count;
            skipped += count;
            if (bytes > maxBytes || skipped > maxNested) {
              receiver.incomplete("archive_byte_limit");
              return;
            }
          }
          continue;
        }
        byte[] data = read(zip, nested ? maxNested : bom ? 1024 * 1024 : 256 * 1024);
        if (data == null) break;
        if (nested)
          scanArchive(
              new ByteArrayInputStream(data),
              location + "!/" + name,
              Component.digest(data),
              depth + 1);
        else if (metadata) {
          Properties props = new Properties();
          props.load(new ByteArrayInputStream(data));
          if (props.getProperty("artifactId") != null) coordinates.add(props);
        } else if (manifest) {
          Manifest values = new Manifest(new ByteArrayInputStream(data));
          title = values.getMainAttributes().getValue("Implementation-Title");
          version = values.getMainAttributes().getValue("Implementation-Version");
          if (title == null) title = values.getMainAttributes().getValue("Bundle-SymbolicName");
          if (version == null) version = values.getMainAttributes().getValue("Bundle-Version");
        } else if (pom) licenses.addAll(licenses(data));
        else {
          try {
            Map<String, Object> value = json.readValue(data, Map.class);
            if ("CycloneDX".equals(value.get("bomFormat"))) imported.add(value);
          } catch (IOException error) {
            receiver.incomplete("invalid_embedded_sbom");
          }
        }
      }
    }
    if (coordinates.size() == 1) {
      Properties p = coordinates.get(0);
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
    } else {
      Component outer =
          new Component(
              title == null ? Component.display(location) : title,
              "",
              version,
              hash,
              title == null ? "artifact-file" : "manifest",
              location);
      if (coordinates.isEmpty()) outer.licenses.addAll(licenses);
      receiver.component(outer, location, true);
      receiver.incomplete(
          coordinates.isEmpty() ? "missing_maven_identity" : "shaded_component_identity_partial");
      for (Properties p : coordinates) {
        Component component =
            new Component(
                p.getProperty("artifactId"),
                p.getProperty("groupId"),
                p.getProperty("version"),
                null,
                "shaded-maven-metadata",
                location);
        receiver.component(component, location, false);
      }
    }
    for (Map<String, Object> bom : imported) receiver.imported(location, bom);
  }

  private byte[] read(InputStream input, int limit) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int count;
    while ((count = input.read(buffer)) >= 0) {
      bytes += count;
      if (output.size() + (long) count > limit || bytes > maxBytes) {
        receiver.incomplete("archive_byte_limit");
        return null;
      }
      output.write(buffer, 0, count);
    }
    return output.toByteArray();
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
        for (int j = 0; j < children.getLength(); j++)
          if (children.item(j).getNodeName().equals("name"))
            result.add(children.item(j).getTextContent().trim());
      }
    } catch (Exception ignored) {
      receiver.incomplete("license_metadata_unreadable");
    }
    return result;
  }
}
