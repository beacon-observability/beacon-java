/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import static io.beacon.security.core.Values.map;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.Events;
import io.beacon.security.core.Identity;
import io.beacon.security.core.Settings;
import io.beacon.security.core.Values;
import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class SbomInventory implements AutoCloseable, ArchiveScanner.Receiver {
  private static final String PROCESS_INSTANCE_ID = Identity.INSTANCE;

  private final Instrumentation instrumentation;
  private final Map<String, String> identity;
  private final Consumer<Map<String, Object>> events;
  private final ObjectMapper json = new ObjectMapper();
  private final String id = "urn:uuid:" + UUID.randomUUID();
  private final String applicationRef;
  private final Path output;
  private final boolean localOutputEnabled =
      Settings.enabled("beacon.security.local-output.enabled", false);
  private final int maxComponents = Settings.limit("beacon.security.sbom.max.components", 10000);
  private final Map<String, Component> components = new TreeMap<>();
  private final Map<String, String> locations = new HashMap<>();
  private final List<DeclaredBom> imported = new ArrayList<>();
  private final Map<String, ArtifactCache> scanned = new LinkedHashMap<>();
  private final Set<String> replacedOrigins = new HashSet<>();
  private Map<String, Map<String, Object>> previousRecords = new TreeMap<>();
  private final Map<String, Map<String, Object>> history = new LinkedHashMap<>();
  private volatile long refreshedAt;
  private volatile String releaseId = "unresolved";
  private final String applicationId;
  private final Set<String> reasons = new LinkedHashSet<>();
  private final ScheduledExecutorService worker =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread thread = new Thread(r, "BeaconSecurity-sbom");
            thread.setDaemon(true);
            return thread;
          });
  private volatile PublishedSnapshot published = new PublishedSnapshot(0, emptyMap());
  private String lastContent;
  private volatile long lastFailure;
  private volatile String lastErrorType;

  public SbomInventory(Instrumentation instrumentation, Consumer<Map<String, Object>> events) {
    this(instrumentation, events, emptyMap());
  }

  public SbomInventory(
      Instrumentation instrumentation,
      Consumer<Map<String, Object>> events,
      Map<String, String> identity) {
    this.identity = new LinkedHashMap<>(identity);
    this.applicationId =
        "app-"
            + Identity.digest(
                identity.getOrDefault("service.namespace", "")
                    + "|"
                    + identity.getOrDefault(
                        "service.name",
                        Settings.text("otel.service.name", "unknown-java-application")));
    this.applicationRef = applicationId;
    this.instrumentation = instrumentation;
    this.events = event -> events.accept(Events.record(event));
    json.getFactory()
        .setStreamReadConstraints(
            StreamReadConstraints.builder().maxNestingDepth(64).maxStringLength(65536).build());
    output =
        Paths.get(
                Settings.text(
                    "beacon.security.sbom.output",
                    Settings.text(
                            "beacon.security.output",
                            "./beacon-security-output/" + PROCESS_INSTANCE_ID)
                        + "/application.cdx.json"))
            .toAbsolutePath();
    reasons.add("runtime_dependency_graph_incomplete");
    if (instrumentation == null) reasons.add("loaded_class_observation_unavailable");
  }

  public Path output() {
    return output;
  }

  public String id() {
    return id;
  }

  public int revision() {
    return published.revision;
  }

  public void start() {
    worker.scheduleWithFixedDelay(
        this::refreshSafely, 0, Settings.limit("beacon.security.sbom.refresh.seconds", 5), SECONDS);
  }

  // Jackson returns erased CycloneDX maps; each document is checked before publication.
  @SuppressWarnings("unchecked")
  public synchronized void refresh() throws IOException {
    components.clear();
    locations.clear();
    imported.clear();
    reasons.clear();
    reasons.add("runtime_dependency_graph_incomplete");
    if (instrumentation == null) reasons.add("loaded_class_observation_unavailable");
    Class<?>[] loaded =
        instrumentation == null ? new Class<?>[0] : instrumentation.getAllLoadedClasses();
    Set<String> observed = new LinkedHashSet<>();
    Set<String> infrastructure = new HashSet<>();
    // URL equality can perform DNS lookups, so deduplicate using its external text form.
    Set<String> processedOrigins = new HashSet<>();
    URL extensionOrigin = origin(SbomInventory.class);
    String extensionLocation = extensionOrigin == null ? null : location(extensionOrigin);
    if (extensionLocation != null) infrastructure.add(extensionLocation);
    for (Class<?> type : loaded) {
      URL origin = origin(type);
      if (origin == null) continue;
      boolean agent = type.getName().equals("io.opentelemetry.javaagent.OpenTelemetryAgent");
      if (!processedOrigins.add(origin.toExternalForm()) && !agent) continue;
      String location = location(origin);
      if (location == null) continue;
      // Application dependencies can use these same namespaces. Only the actual
      // agent entry point and this extension identify infrastructure artifacts;
      // a nested dependency must never exclude its enclosing application JAR.
      if (agent) infrastructure.add(location);
      observed.add(location);
    }
    Set<String> roots = new LinkedHashSet<>();
    for (String entry :
        System.getProperty("java.class.path", "").split(Pattern.quote(File.pathSeparator))) {
      if (!entry.isEmpty()) roots.add(Paths.get(entry).toAbsolutePath().normalize().toString());
    }
    for (String location : observed) roots.add(outer(location));
    scanned.keySet().retainAll(roots);
    int rootCount = 0;
    for (String root : roots) {
      if (infrastructure.contains(root)) continue;
      if (++rootCount > maxComponents) {
        incomplete("artifact_count_limit");
        break;
      }
      Path path = Paths.get(root);
      String fingerprint = ArtifactCache.fingerprint(path);
      ArtifactCache cached = scanned.get(root);
      if (cached == null || !cached.reusable(fingerprint)) {
        if (cached != null && !cached.fingerprint.equals(fingerprint)) replacedOrigins.add(root);
        cached = new ArtifactCache(path, fingerprint);
        scanned.put(root, cached);
      }
      cached.replay(this);
    }
    String buildFile = Settings.text("beacon.security.sbom.build.file", "");
    if (!buildFile.isEmpty()) {
      Path path = Paths.get(buildFile);
      try {
        if (Files.size(path) > 1024 * 1024) incomplete("build_sbom_byte_limit");
        else {
          Map<String, Object> bom = json.readValue(path.toFile(), Map.class);
          if (!"CycloneDX".equals(bom.get("bomFormat"))) incomplete("invalid_build_sbom");
          else
            imported(
                Settings.text("beacon.security.sbom.build.artifact", "external-build-sbom"), bom);
        }
      } catch (Exception error) {
        incomplete("build_sbom_unreadable");
      }
    }
    for (String location : observed) {
      String ref = locations.get(location);
      if (ref == null && location.endsWith("!/BOOT-INF/classes"))
        ref = locations.get(outer(location));
      if (ref == null && location.endsWith("!/WEB-INF/classes"))
        ref = locations.get(outer(location));
      Component component = ref == null ? null : components.get(ref);
      if (component != null && !replacedOrigins.contains(outer(location))) component.loaded = true;
      else if (component != null) incomplete("replaced_artifact_loaded_class_identity_unknown");
    }
    for (String location : new ArrayList<>(locations.keySet()))
      if (replacedOrigins.contains(outer(location))) locations.remove(location);
    publish();
    refreshedAt = System.currentTimeMillis();
    events.accept(health());
  }

  public Map<String, Object> health() {
    return map(
        "event_name",
        "beacon.security.sbom.health",
        "status",
        lastFailure > refreshedAt ? "degraded" : revision() == 0 ? "initializing" : "current",
        "sbom_id",
        id,
        "revision",
        revision(),
        "application_id",
        applicationId,
        "release_id",
        releaseId,
        "instance_id",
        PROCESS_INSTANCE_ID,
        "last_refresh_at",
        refreshedAt == 0 ? null : Events.timestamp(refreshedAt),
        "last_failure_at",
        lastFailure == 0 ? null : Events.timestamp(lastFailure),
        "last_error_type",
        lastErrorType,
        "reasons",
        new ArrayList<>(reasons),
        "dropped_observations",
        0,
        "current_components",
        previousRecords.size(),
        "history_count",
        history.size(),
        "completeness",
        "incomplete");
  }

  private void refreshSafely() {
    try {
      refresh();
    } catch (Throwable error) {
      long now = System.currentTimeMillis();
      boolean report = now - lastFailure > 30000;
      lastFailure = now;
      lastErrorType = error.getClass().getSimpleName();
      if (report) {
        System.err.println(
            "[BeaconSecurity] SBOM update failed: " + error.getClass().getSimpleName());
        events.accept(
            map(
                "event_name",
                "beacon.security.sbom.update_failed",
                "sbom_id",
                id,
                "revision",
                revision(),
                "error_type",
                error.getClass().getSimpleName()));
      }
    }
  }

  @Override
  public void component(Component component, String location, boolean primary) {
    if (components.size() >= maxComponents && !components.containsKey(component.ref)) {
      incomplete("component_count_limit");
      return;
    }
    Component existing = components.get(component.ref);
    if (existing == null) {
      existing = component;
      components.put(existing.ref, existing);
    }
    existing.locations.add(location);
    if (primary) locations.put(location, existing.ref);
  }

  @Override
  public void imported(String location, Map<String, Object> bom) {
    if (imported.size() < 64) imported.add(new DeclaredBom(location, bom));
    else incomplete("embedded_sbom_limit");
  }

  @Override
  public void incomplete(String reason) {
    if (reasons.size() < 128) reasons.add(reason);
  }

  public Map<String, Object> resolve(String className, ClassLoader loader) {
    PublishedSnapshot snapshot = published;
    Map<String, Object> result =
        map(
            "sbom_id",
            id,
            "revision",
            snapshot.revision,
            "application_id",
            applicationId,
            "release_id",
            snapshot.releaseId,
            "status",
            "unresolved");
    try {
      // Called for an executing callsite, with its defining loader. No initialization, scans or
      // hashes here.
      URL origin = origin(Class.forName(className, false, loader));
      String location = origin == null ? null : location(origin);
      if (location != null) {
        String ref = snapshot.locations.get(location);
        if (ref == null
            && (location.endsWith("!/BOOT-INF/classes") || location.endsWith("!/WEB-INF/classes")))
          ref = snapshot.locations.get(outer(location));
        if (ref != null) {
          result.put("bom-ref", ref);
          result.put("status", "resolved");
        }
      }
    } catch (Throwable ignored) {
      // Component resolution is best effort and must not affect the instrumented application.
    }
    return Events.component(result, applicationId);
  }

  // The generated CycloneDX document has a metadata map created in this method.
  @SuppressWarnings("unchecked")
  private void publish() throws IOException {
    int revision = published.revision + 1;
    Map<String, Map<String, Object>> records = new TreeMap<>();
    Map<String, List<String>> purls = new HashMap<>();
    for (Component component : components.values()) {
      records.put(component.ref, component.json());
      if (!component.purl.isEmpty())
        purls.computeIfAbsent(component.purl, key -> new ArrayList<>()).add(component.ref);
    }
    List<Object> dependencies = mergeDeclared(records, purls);
    Set<String> artifacts = new TreeSet<>();
    boolean artifactIdentityComplete = true;
    for (Component component : components.values()) {
      if (component.hash != null) artifacts.add(component.hash);
      else if (!component.source.equals("shaded-maven-metadata") && !component.declared)
        artifactIdentityComplete = false;
    }
    String nextReleaseId = "release-" + Identity.digest(applicationId + "|" + artifacts);
    List<Object> properties = new ArrayList<>();
    properties.add(map("name", "source", "value", "beacon_security"));
    properties.add(map("name", "beacon:security:application-id", "value", applicationId));
    properties.add(map("name", "beacon:security:release-id", "value", nextReleaseId));
    properties.add(
        map(
            "name",
            "beacon:security:release:identity-status",
            "value",
            artifactIdentityComplete && !artifacts.isEmpty() ? "artifact_digest" : "incomplete"));
    properties.add(
        map(
            "name",
            "beacon:security:sbom:quality",
            "value",
            json.writeValueAsString(quality(records))));
    properties.add(
        map("name", "beacon:security:process-instance-id", "value", PROCESS_INSTANCE_ID));
    properties.add(
        map(
            "name",
            "beacon:security:sbom:completeness-reasons",
            "value",
            String.join(",", reasons)));
    properties.add(
        map(
            "name",
            "beacon:security:sbom:loaded-semantics",
            "value",
            "runtime_load_observed_not_execution"));
    Map<String, Object> application =
        map(
            "type",
            "application",
            "bom-ref",
            applicationRef,
            "name",
            Values.bounded(
                identity.getOrDefault(
                    "service.name", Settings.text("otel.service.name", "unknown-java-application")),
                512));
    String version = identity.get("service.version");
    if (version != null && !version.isEmpty())
      application.put("version", Values.bounded(version, 256));
    List<Object> identityProperties = new ArrayList<>();
    identity.forEach(
        (key, value) ->
            identityProperties.add(
                map("name", "otel:" + key, "value", Values.bounded(value, 512))));
    if (!identityProperties.isEmpty()) application.put("properties", identityProperties);
    Map<String, Object> document =
        map(
            "bomFormat",
            "CycloneDX",
            "specVersion",
            "1.7",
            "serialNumber",
            id,
            "version",
            revision,
            "metadata",
            map(
                "lifecycles",
                singletonList(map("phase", "operations")),
                "component",
                application,
                "tools",
                map(
                    "components",
                    asList(
                        map(
                            "type",
                            "application",
                            "name",
                            "Beacon Java Agent",
                            "version",
                            Identity.VERSION),
                        map(
                            "type",
                            "platform",
                            "name",
                            Values.bounded(System.getProperty("java.runtime.name", "JVM"), 256),
                            "version",
                            Values.bounded(
                                System.getProperty("java.runtime.version", "unknown"), 256))))),
            "components",
            new ArrayList<>(records.values()),
            "dependencies",
            dependencies,
            "compositions",
            singletonList(
                map("aggregate", "incomplete", "assemblies", singletonList(applicationRef))),
            "properties",
            properties);
    Map<String, Object> stable = new LinkedHashMap<>(document);
    stable.remove("version");
    String content = Component.digest(json.writeValueAsBytes(stable));
    if (content.equals(lastContent)) return;
    List<Map<String, Object>> snapshotEvents =
        DependencySnapshot.events(
            map(
                "event_name",
                "beacon.security.sbom.snapshot",
                "sbom_id",
                id,
                "revision",
                revision,
                "application_id",
                applicationId,
                "release_id",
                nextReleaseId,
                "instance_id",
                PROCESS_INSTANCE_ID,
                "status",
                "current",
                "completeness",
                "incomplete",
                "reasons",
                new ArrayList<>(reasons)),
            records.values());
    ((Map<String, Object>) document.get("metadata")).put("timestamp", Events.now());
    if (localOutputEnabled) {
      Files.createDirectories(output.getParent());
      Path temporary = Files.createTempFile(output.getParent(), ".sbom-", ".json");
      try {
        json.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), document);
        Files.move(
            temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      } finally {
        Files.deleteIfExists(temporary);
      }
    }
    lastContent = content;
    // Readers must observe a component mapping and its revision from the same completed
    // publication.
    releaseId = nextReleaseId;
    published = new PublishedSnapshot(revision, locations, releaseId);
    for (Map.Entry<String, Map<String, Object>> entry : records.entrySet()) {
      String ref = entry.getKey();
      Map<String, Object> record = entry.getValue();
      if (!record.equals(previousRecords.get(ref))) {
        Map<String, Object> historical = history.get(ref);
        if (historical == null && history.size() < maxComponents) {
          historical = map("bom-ref", ref, "first_seen", Events.now());
          history.put(ref, historical);
        }
        if (historical != null) {
          historical.put("state", "current");
          historical.put("last_changed_at", Events.now());
        }
      }
    }
    for (String ref : previousRecords.keySet())
      if (!records.containsKey(ref)) {
        Map<String, Object> historical = history.get(ref);
        if (historical != null) {
          historical.put("state", "removed");
          historical.put("last_changed_at", Events.now());
        }
      }
    previousRecords = new TreeMap<>(records);
    if (localOutputEnabled) writeHistory();
    for (Map<String, Object> event : snapshotEvents) events.accept(event);
  }

  private List<Object> mergeDeclared(
      Map<String, Map<String, Object>> records, Map<String, List<String>> purls) {
    Map<String, Set<String>> edges = new LinkedHashMap<>();
    Set<String> unresolvedEdges = new HashSet<>();
    for (DeclaredBom declaration : imported) {
      Map<String, String> refs = new HashMap<>();
      Object metadata = declaration.value.get("metadata");
      if (metadata instanceof Map) {
        Object root = ((Map<?, ?>) metadata).get("component");
        if (root instanceof Map && ((Map<?, ?>) root).get("bom-ref") instanceof String && true)
          refs.put(
              (String) ((Map<?, ?>) root).get("bom-ref"),
              locations.getOrDefault(declaration.location, applicationRef));
      }
      Object list = declaration.value.get("components");
      if (list instanceof List)
        for (Object entry : (List<?>) list) {
          if (!(entry instanceof Map) || records.size() >= maxComponents) {
            incomplete("imported_component_limit_or_invalid");
            break;
          }
          Map<?, ?> value = (Map<?, ?>) entry;
          String oldRef = string(value.get("bom-ref"));
          String purl = string(value.get("purl"));
          List<String> matches = purls.get(purl);
          if (matches != null && matches.size() == 1) {
            refs.put(oldRef, matches.get(0));
            enrich(records.get(matches.get(0)), value);
            continue;
          }
          Component component =
              new Component(
                  string(value.get("name")),
                  string(value.get("group")),
                  string(value.get("version")),
                  null,
                  "build-sbom",
                  declaration.location + "|" + oldRef);
          component.declared = true;
          Map<String, Object> record = component.json();
          enrich(record, value);
          if (!purl.isEmpty() && purl.startsWith("pkg:"))
            record.put("purl", Values.bounded(purl, 2048));
          records.put(component.ref, record);
          if (!oldRef.isEmpty()) refs.put(oldRef, component.ref);
          if (matches != null && matches.size() > 1) incomplete("ambiguous_declared_component");
        }
      Object graph = declaration.value.get("dependencies");
      if (graph instanceof List)
        for (Object entry : (List<?>) graph) {
          if (!(entry instanceof Map)) continue;
          Map<?, ?> dependency = (Map<?, ?>) entry;
          String from = refs.get(string(dependency.get("ref")));
          Object targets = dependency.get("dependsOn");
          if (from == null || !(targets instanceof List)) {
            incomplete("unresolved_declared_dependency");
            continue;
          }
          Set<String> to = edges.computeIfAbsent(from, ignored -> new LinkedHashSet<>());
          for (Object target : (List<?>) targets) {
            String mapped = refs.get(string(target));
            if (mapped != null) to.add(mapped);
            else {
              incomplete("unresolved_declared_dependency");
              unresolvedEdges.add(from);
            }
          }
        }
    }
    List<Object> result = new ArrayList<>();
    for (Map.Entry<String, Set<String>> edge : edges.entrySet()) {
      if (edge.getValue().isEmpty() && unresolvedEdges.contains(edge.getKey())) continue;
      result.add(map("ref", edge.getKey(), "dependsOn", new ArrayList<>(edge.getValue())));
    }
    return result;
  }

  private void writeHistory() {
    Path path = output.resolveSibling("sbom-history.json");
    Path temp = null;
    try {
      temp = Files.createTempFile(output.getParent(), ".sbom-history-", ".json");
      json.writeValue(
          temp.toFile(),
          map(
              "schema_version",
              1,
              "source",
              "beacon_security",
              "sbom_id",
              id,
              "revision",
              revision(),
              "application_id",
              applicationId,
              "release_id",
              releaseId,
              "updated_at",
              Events.now(),
              "entries",
              new ArrayList<>(history.values()),
              "history_limit",
              maxComponents,
              "history_complete",
              history.size() < maxComponents));
      Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException error) {
      events.accept(map("event_name", "beacon.security.sbom.history_write_failed", "sbom_id", id));
    } finally {
      if (temp != null)
        try {
          Files.deleteIfExists(temp);
        } catch (IOException ignored) {
          // The temporary file is already unreachable after a failed atomic replacement.
        }
    }
  }

  private static Map<String, Object> quality(Map<String, Map<String, Object>> records) {
    int purl = 0;
    int version = 0;
    int hash = 0;
    int license = 0;
    int loaded = 0;
    for (Map<String, Object> record : records.values()) {
      if (record.containsKey("purl")) purl++;
      if (record.containsKey("version")) version++;
      if (record.containsKey("hashes")) hash++;
      if (record.containsKey("licenses")) license++;
      for (Object property : (List<?>) record.get("properties")) {
        Map<?, ?> item = (Map<?, ?>) property;
        if ("beacon:security:sbom:loaded".equals(item.get("name"))
            && "true".equals(item.get("value"))) loaded++;
      }
    }
    return map(
        "components",
        records.size(),
        "with_purl",
        purl,
        "with_version",
        version,
        "with_hash",
        hash,
        "with_license",
        license,
        "loaded_components",
        loaded);
  }

  // Component properties are created internally as a mutable List<Object>.
  @SuppressWarnings("unchecked")
  private static void enrich(Map<String, Object> record, Map<?, ?> declaration) {
    Object licenses = declaration.get("licenses");
    if (!record.containsKey("licenses") && licenses instanceof List) {
      List<Object> accepted = new ArrayList<>();
      for (Object entry : (List<?>) licenses) {
        if (accepted.size() >= 16 || !(entry instanceof Map)) break;
        Object license = ((Map<?, ?>) entry).get("license");
        if (license instanceof Map) {
          String name = string(((Map<?, ?>) license).get("name"));
          if (name.isEmpty()) name = string(((Map<?, ?>) license).get("id"));
          if (!name.isEmpty()) accepted.add(map("license", map("name", name)));
        }
      }
      if (!accepted.isEmpty()) {
        record.put("licenses", accepted);
        ((List<Object>) record.get("properties"))
            .add(
                map(
                    "name",
                    "beacon:security:sbom:license-source",
                    "value",
                    "build-sbom-declaration"));
      }
    }
  }

  private static String string(Object value) {
    return value instanceof String ? Values.bounded((String) value, 2048) : "";
  }

  private static URL origin(Class<?> type) {
    try {
      ProtectionDomain domain = type.getProtectionDomain();
      CodeSource source = domain == null ? null : domain.getCodeSource();
      return source == null ? null : source.getLocation();
    } catch (SecurityException ignored) {
      return null;
    }
  }

  static String location(URL url) {
    try {
      String path = URLDecoder.decode(url.toExternalForm().replace("+", "%2B"), "UTF-8");
      while (path.startsWith("jar:") || path.startsWith("nested:") || path.startsWith("file:"))
        path = path.substring(path.indexOf(':') + 1);
      if (!path.startsWith("/")) return null;
      path = path.replace("/!", "!/");
      while (path.endsWith("/") || path.endsWith("!")) path = path.substring(0, path.length() - 1);
      int split = path.indexOf("!/");
      return Paths.get(split < 0 ? path : path.substring(0, split)).toAbsolutePath().normalize()
          + (split < 0 ? "" : path.substring(split));
    } catch (Exception ignored) {
      return null;
    }
  }

  private static String outer(String location) {
    int split = location.indexOf("!/");
    return split < 0 ? location : location.substring(0, split);
  }

  @Override
  public void close() {
    worker.shutdown();
    try {
      worker.awaitTermination(3, SECONDS);
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
    }
  }

  private static final class DeclaredBom {
    final String location;
    final Map<String, Object> value;

    DeclaredBom(String location, Map<String, Object> value) {
      this.location = location;
      this.value = value;
    }
  }

  private static final class PublishedSnapshot {
    final int revision;
    final Map<String, String> locations;
    final String releaseId;

    PublishedSnapshot(int revision, Map<String, String> locations) {
      this(revision, locations, "unresolved");
    }

    PublishedSnapshot(int revision, Map<String, String> locations, String releaseId) {
      this.revision = revision;
      this.releaseId = releaseId;
      this.locations = Collections.unmodifiableMap(new HashMap<>(locations));
    }
  }
}
