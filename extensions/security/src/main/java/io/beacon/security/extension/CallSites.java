/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

final class CallSites {
  private CallSites() {}

  static boolean isJacksonReader(String owner) {
    // Keep application class names distinct from the extension's relocated Jackson dependency.
    return owner.startsWith("com/fasterxml/")
        && (owner.endsWith("/jackson/databind/ObjectMapper")
            || owner.endsWith("/jackson/databind/ObjectReader"));
  }

  static boolean matches(String owner, String method) {
    if (isJacksonReader(owner)) return method.equals("readValue");
    if (owner.equals("java/io/BufferedReader")) return method.equals("readLine");
    if (owner.equals("org/springframework/util/StringUtils")) return method.equals("toStringArray");
    if (owner.equals("java/util/Collections")) return method.equals("list");
    if (owner.equals("java/util/Enumeration")) return method.equals("nextElement");
    if (owner.equals("java/lang/String"))
      return method.equals("<init>")
          || method.equals("concat")
          || method.equals("substring")
          || method.equals("subSequence")
          || method.equals("format")
          || method.startsWith("replace")
          || method.equals("valueOf")
          || method.equals("trim")
          || method.startsWith("strip")
          || method.equals("toLowerCase")
          || method.equals("toUpperCase")
          || method.equals("join")
          || method.equals("toString");
    if (owner.equals("java/lang/StringBuilder") || owner.equals("java/lang/StringBuffer"))
      return method.equals("<init>")
          || method.equals("append")
          || method.equals("appendCodePoint")
          || method.equals("insert")
          || method.equals("delete")
          || method.equals("deleteCharAt")
          || method.equals("replace")
          || method.equals("reverse")
          || method.equals("setCharAt")
          || method.equals("setLength")
          || method.equals("toString")
          || method.equals("substring")
          || method.equals("subSequence");
    if (owner.startsWith("java/sql/"))
      return method.startsWith("execute")
          || method.equals("prepareStatement")
          || method.equals("prepareCall");
    if (owner.equals("java/lang/Runtime")) return method.equals("exec");
    if (owner.equals("java/lang/ProcessBuilder")) return method.equals("start");
    if (owner.equals("java/io/File"))
      return method.equals("<init>")
          || method.equals("toPath")
          || method.equals("getPath")
          || method.equals("getAbsolutePath")
          || method.equals("getCanonicalPath")
          || method.equals("getAbsoluteFile")
          || method.equals("getCanonicalFile")
          || method.equals("toURI")
          || method.equals("toString");
    if (owner.equals("java/nio/file/Path") || owner.equals("java/nio/file/Paths"))
      return method.equals("get")
          || method.equals("of")
          || method.equals("resolve")
          || method.equals("resolveSibling")
          || method.equals("normalize")
          || method.equals("toAbsolutePath")
          || method.equals("toRealPath")
          || method.equals("toFile")
          || method.equals("toUri")
          || method.equals("toString")
          || method.equals("getFileName")
          || method.equals("getParent")
          || method.equals("subpath");
    if (owner.equals("java/io/FileInputStream")
        || owner.equals("java/io/FileOutputStream")
        || owner.equals("java/io/RandomAccessFile")) return method.equals("<init>");
    if (owner.equals("java/nio/file/Files"))
      return method.startsWith("read")
          || method.startsWith("write")
          || method.startsWith("new")
          || method.startsWith("delete")
          || method.equals("copy")
          || method.equals("move");
    if (owner.equals("java/net/URLEncoder") || owner.equals("java/net/URLDecoder")) return true;
    if (owner.equals("java/net/URI") || owner.equals("java/net/URL"))
      return method.equals("<init>")
          || method.equals("create")
          || method.equals("resolve")
          || method.equals("normalize")
          || method.equals("toURL")
          || method.equals("toURI")
          || method.equals("toString")
          || method.equals("toASCIIString")
          || method.equals("toExternalForm")
          || method.equals("openConnection")
          || method.equals("openStream")
          || method.equals("getContent")
          || method.equals("getHost")
          || method.equals("getPath")
          || method.equals("getQuery")
          || method.equals("getAuthority")
          || method.equals("getFile")
          || method.equals("getScheme");
    if (owner.startsWith("java/net/") && owner.contains("URLConnection"))
      return method.equals("connect")
          || method.equals("getInputStream")
          || method.equals("getOutputStream")
          || method.equals("getResponseCode");
    if (owner.startsWith("java/net/http/"))
      return method.equals("send")
          || method.equals("sendAsync")
          || method.equals("newBuilder")
          || method.equals("uri")
          || method.equals("build");
    if (owner.startsWith("okhttp3/"))
      return method.equals("url")
          || method.equals("build")
          || method.equals("newCall")
          || method.equals("execute")
          || method.equals("enqueue")
          || method.equals("<init>");
    if (owner.startsWith("org/apache/http/") || owner.startsWith("org/apache/hc/"))
      return method.startsWith("execute")
          || method.equals("<init>")
          || method.equals("setURI")
          || method.equals("setUri")
          || method.equals("build");
    if (owner.contains("StringEscapeUtils"))
      return method.startsWith("escape") || method.startsWith("unescape");
    return method.equals("execute")
        || method.equals("executeQuery")
        || method.equals("executeUpdate")
        || method.equals("prepareStatement")
        || method.equals("prepareCall");
  }

  static boolean isRestTemplateCall(String owner, String method) {
    if (!owner.equals("org/springframework/web/client/RestTemplate")
        && !owner.equals("org/springframework/web/client/RestOperations")) return false;
    // RestTemplate convenience methods delegate here. Observing both layers
    // would count the same HTTP attempt twice.
    return method.equals("execute");
  }
}
