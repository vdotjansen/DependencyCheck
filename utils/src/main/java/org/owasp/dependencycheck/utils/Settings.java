/*
 * This file is part of dependency-check-utils.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import com.google.gson.Gson;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A simple settings container that wraps the dependencycheck.properties file.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public final class Settings {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Settings.class);
    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "dependencycheck.properties";
    /**
     * Array separator.
     */
    private static final String ARRAY_SEP = ",";
    /**
     * The properties.
     */
    private Properties props = null;
    /**
     * The collection of properties that should be masked when logged.
     */
    private List<Predicate<String>> maskedKeys;
    /**
     * A reference to the temporary directory; used in case it needs to be
     * deleted during cleanup.
     */
    private File tempDirectory = null;

    //<editor-fold defaultstate="collapsed" desc="KEYS used to access settings">
    /**
     * The collection of keys used within the properties file.
     */
    //suppress hard-coded password rule
    @SuppressWarnings("squid:S2068")
    public static final class KEYS {

        /**
         * The key to obtain the application name.
         */
        public static final String APPLICATION_NAME = "odc.application.name";
        /**
         * The key to obtain the application version.
         */
        public static final String APPLICATION_VERSION = "odc.application.version";
        /**
         * The key to obtain the URL to retrieve the current release version
         * from.
         */
        public static final String ENGINE_VERSION_CHECK_URL = "engine.version.url";
        /**
         * The properties key indicating whether or not the cached data sources
         * should be updated.
         */
        public static final String AUTO_UPDATE = "odc.autoupdate";
        /**
         * The database driver class name. If this is not in the properties file
         * the embedded database is used.
         */
        public static final String DB_DRIVER_NAME = "data.driver_name";
        /**
         * The database driver class name. If this is not in the properties file
         * the embedded database is used.
         */
        public static final String DB_DRIVER_PATH = "data.driver_path";
        /**
         * The database connection string. If this is not in the properties file
         * the embedded database is used.
         */
        public static final String DB_CONNECTION_STRING = "data.connection_string";
        /**
         * The username to use when connecting to the database.
         */
        public static final String DB_USER = "data.user";
        /**
         * The password to authenticate to the database.
         */
        public static final String DB_PASSWORD = "data.password";
        /**
         * The base path to use for the data directory (for embedded db and
         * other cached resources from the Internet).
         */
        public static final String DATA_DIRECTORY = "data.directory";
        /**
         * The base path to use for the H2 data directory (for embedded db).
         */
        public static final String H2_DATA_DIRECTORY = "data.h2.directory";
        /**
         * The database file name.
         */
        public static final String DB_FILE_NAME = "data.file_name";
        /**
         * The database schema version.
         */
        public static final String DB_VERSION = "data.version";
        /**
         * The starts with filter used to exclude CVE entries from the database.
         * By default this is set to 'cpe:2.3:a:' which limits the CVEs imported
         * to just those that are related to applications. If this were set to
         * just 'cpe:2.3:' the OS, hardware, and application related CVEs would
         * be imported.
         */
        public static final String CVE_CPE_STARTS_WITH_FILTER = "cve.cpe.startswith.filter";
        /**
         * The properties key for the URL to retrieve the recently modified and
         * added CVE entries (last 8 days) using the JSON data feeds.
         */
        public static final String CVE_MODIFIED_JSON = "cve.url.modified";
        /**
         * The properties key for the original/modified URL to retrieve the
         * recently modified and added CVE entries (last 8 days). Note, this is
         * only used to compare against CVE_MODIFIED_JSON.
         */
        public static final String CVE_ORIGINAL_JSON = "cve.url.original";
        /**
         * The properties key for the URL to retrieve the recently modified and
         * added CVE entries (last 8 days) using the JSON data feeds.
         */
        public static final String CVE_BASE_JSON = "cve.url.base";
        /**
         * The properties key for the URL to retrieve the recently modified and
         * added CVE entries (last 8 days).
         */
        public static final String CVE_MODIFIED_VALID_FOR_DAYS = "cve.url.modified.validfordays";
        /**
         * The properties key to control the skipping of the check for CVE
         * updates.
         */
        public static final String CVE_CHECK_VALID_FOR_HOURS = "cve.check.validforhours";
        /**
         * The properties key for the telling us how many cve.url.* URLs exists.
         * This is used in combination with CVE_BASE_URL to be able to retrieve
         * the URLs for all of the files that make up the NVD CVE listing.
         */
        public static final String CVE_START_YEAR = "cve.startyear";
        /**
         * The properties key that indicates how often the CPE data needs to be
         * updated.
         */
        public static final String CPE_MODIFIED_VALID_FOR_DAYS = "cpe.validfordays";
        /**
         * The properties key for the URL to retrieve the CPE.
         */
        public static final String CPE_URL = "cpe.url";
        /**
         * Whether or not if using basic auth with a proxy the system setting
         * 'jdk.http.auth.tunneling.disabledSchemes' should be set to an empty
         * string.
         */
        public static final String PROXY_DISABLE_SCHEMAS = "proxy.disableSchemas";
        /**
         * The properties key for the proxy server.
         */
        public static final String PROXY_SERVER = "proxy.server";
        /**
         * The properties key for the proxy port - this must be an integer
         * value.
         */
        public static final String PROXY_PORT = "proxy.port";
        /**
         * The properties key for the proxy username.
         */
        public static final String PROXY_USERNAME = "proxy.username";
        /**
         * The properties key for the proxy password.
         */
        public static final String PROXY_PASSWORD = "proxy.password";
        /**
         * The properties key for the non proxy hosts.
         */
        public static final String PROXY_NON_PROXY_HOSTS = "proxy.nonproxyhosts";
        /**
         * The properties key for the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connection.timeout";
        /**
         * The location of the temporary directory.
         */
        public static final String TEMP_DIRECTORY = "temp.directory";
        /**
         * The maximum number of threads to allocate when downloading files.
         */
        public static final String MAX_DOWNLOAD_THREAD_POOL_SIZE = "max.download.threads";
        /**
         * The properties key for the analysis timeout.
         */
        public static final String ANALYSIS_TIMEOUT = "odc.analysis.timeout";
        /**
         * The key for the suppression file.
         */
        public static final String SUPPRESSION_FILE = "suppression.file";
        /**
         * The key for the hint file.
         */
        public static final String HINTS_FILE = "hints.file";
        /**
         * The key for the property that controls what CVSS scores are
         * considered failing test cases for the JUNIT repor.
         */
        public static final String JUNIT_FAIL_ON_CVSS = "junit.fail.on.cvss";

        /**
         * The properties key for whether the Jar Analyzer is enabled.
         */
        public static final String ANALYZER_JAR_ENABLED = "analyzer.jar.enabled";
        /**
         * The properties key for whether experimental analyzers are loaded.
         */
        public static final String ANALYZER_EXPERIMENTAL_ENABLED = "analyzer.experimental.enabled";
        /**
         * The properties key for whether experimental analyzers are loaded.
         */
        public static final String ANALYZER_RETIRED_ENABLED = "analyzer.retired.enabled";
        /**
         * The properties key for whether the Archive analyzer is enabled.
         */
        public static final String ANALYZER_ARCHIVE_ENABLED = "analyzer.archive.enabled";
        /**
         * The properties key for whether the node.js package analyzer is
         * enabled.
         */
        public static final String ANALYZER_NODE_PACKAGE_ENABLED = "analyzer.node.package.enabled";
        /**
         * The properties key for whether the Node Audit analyzer is enabled.
         */
        public static final String ANALYZER_NODE_AUDIT_ENABLED = "analyzer.node.audit.enabled";
        /**
         * The properties key for supplying the URL to the Node Audit API.
         */
        public static final String ANALYZER_NODE_AUDIT_URL = "analyzer.node.audit.url";
        /**
         * The properties key for configure whether the Node Audit analyzer should skip devDependencies.
         */
        public static final String ANALYZER_NODE_AUDIT_SKIPDEV = "analyzer.node.audit.skipdev";
        /**
         * The properties key for whether node audit analyzer results will be
         * cached.
         */
        public static final String ANALYZER_NODE_AUDIT_USE_CACHE = "analyzer.node.audit.use.cache";
        /**
         * The properties key for whether the RetireJS analyzer is enabled.
         */
        public static final String ANALYZER_RETIREJS_ENABLED = "analyzer.retirejs.enabled";
        /**
         * The properties key for whether the RetireJS analyzer file content
         * filters.
         */
        public static final String ANALYZER_RETIREJS_FILTERS = "analyzer.retirejs.filters";
        /**
         * The properties key for whether the RetireJS analyzer should filter
         * out non-vulnerable dependencies.
         */
        public static final String ANALYZER_RETIREJS_FILTER_NON_VULNERABLE = "analyzer.retirejs.filternonvulnerable";
        /**
         * The properties key for defining the URL to the RetireJS repository.
         */
        public static final String ANALYZER_RETIREJS_REPO_JS_URL = "analyzer.retirejs.repo.js.url";
        /**
         * The properties key for defining whether the RetireJS repository will
         * be updated regardless of the autoupdate settings.
         */
        public static final String ANALYZER_RETIREJS_FORCEUPDATE = "analyzer.retirejs.forceupdate";
        /**
         * The properties key to control the skipping of the check for CVE
         * updates.
         */
        public static final String ANALYZER_RETIREJS_REPO_VALID_FOR_HOURS = "analyzer.retirejs.repo.validforhours";
        /**
         * The properties key for whether the composer lock file analyzer is
         * enabled.
         */
        public static final String ANALYZER_COMPOSER_LOCK_ENABLED = "analyzer.composer.lock.enabled";
        /**
         * The properties key for whether the Python Distribution analyzer is
         * enabled.
         */
        public static final String ANALYZER_PYTHON_DISTRIBUTION_ENABLED = "analyzer.python.distribution.enabled";
        /**
         * The properties key for whether the Python Package analyzer is
         * enabled.
         */
        public static final String ANALYZER_PYTHON_PACKAGE_ENABLED = "analyzer.python.package.enabled";
        /**
         * The properties key for whether the Golang Mod analyzer is enabled.
         */
        public static final String ANALYZER_GOLANG_MOD_ENABLED = "analyzer.golang.mod.enabled";
        /**
         * The path to go, if available.
         */
        public static final String ANALYZER_GOLANG_PATH = "analyzer.golang.path";
        /**
         * The properties key for whether the Golang Dep analyzer is enabled.
         */
        public static final String ANALYZER_GOLANG_DEP_ENABLED = "analyzer.golang.dep.enabled";
        /**
         * The properties key for whether the Ruby Gemspec Analyzer is enabled.
         */
        public static final String ANALYZER_RUBY_GEMSPEC_ENABLED = "analyzer.ruby.gemspec.enabled";
        /**
         * The properties key for whether the Autoconf analyzer is enabled.
         */
        public static final String ANALYZER_AUTOCONF_ENABLED = "analyzer.autoconf.enabled";
        /**
         * The properties key for whether the CMake analyzer is enabled.
         */
        public static final String ANALYZER_CMAKE_ENABLED = "analyzer.cmake.enabled";
        /**
         * The properties key for whether the Ruby Bundler Audit analyzer is
         * enabled.
         */
        public static final String ANALYZER_BUNDLE_AUDIT_ENABLED = "analyzer.bundle.audit.enabled";
        /**
         * The properties key for whether the .NET Assembly analyzer is enabled.
         */
        public static final String ANALYZER_ASSEMBLY_ENABLED = "analyzer.assembly.enabled";
        /**
         * The properties key for whether the .NET Nuspec analyzer is enabled.
         */
        public static final String ANALYZER_NUSPEC_ENABLED = "analyzer.nuspec.enabled";
        /**
         * The properties key for whether the .NET Nuget packages.config
         * analyzer is enabled.
         */
        public static final String ANALYZER_NUGETCONF_ENABLED = "analyzer.nugetconf.enabled";
        /**
         * The properties key for whether the .NET MSBuild Project analyzer is
         * enabled.
         */
        public static final String ANALYZER_MSBUILD_PROJECT_ENABLED = "analyzer.msbuildproject.enabled";
        /**
         * The properties key for whether the Nexus analyzer is enabled.
         */
        public static final String ANALYZER_NEXUS_ENABLED = "analyzer.nexus.enabled";
        /**
         * The properties key for the Nexus search URL.
         */
        public static final String ANALYZER_NEXUS_URL = "analyzer.nexus.url";
        /**
         * The properties key for the Nexus search credentials username.
         */
        public static final String ANALYZER_NEXUS_USER = "analyzer.nexus.username";
        /**
         * The properties key for the Nexus search credentials password.
         */
        public static final String ANALYZER_NEXUS_PASSWORD = "analyzer.nexus.password";
        /**
         * The properties key for using the proxy to reach Nexus.
         */
        public static final String ANALYZER_NEXUS_USES_PROXY = "analyzer.nexus.proxy";
        /**
         * The properties key for whether the Artifactory analyzer is enabled.
         */
        public static final String ANALYZER_ARTIFACTORY_ENABLED = "analyzer.artifactory.enabled";
        /**
         * The properties key for the Artifactory search URL.
         */
        public static final String ANALYZER_ARTIFACTORY_URL = "analyzer.artifactory.url";
        /**
         * The properties key for the Artifactory username.
         */
        public static final String ANALYZER_ARTIFACTORY_API_USERNAME = "analyzer.artifactory.api.username";
        /**
         * The properties key for the Artifactory API token.
         */
        public static final String ANALYZER_ARTIFACTORY_API_TOKEN = "analyzer.artifactory.api.token";
        /**
         * The properties key for the Artifactory bearer token
         * (https://www.jfrog.com/confluence/display/RTF/Access+Tokens). It can
         * be generated using:
         * <pre>curl -u yourUserName -X POST \
         *    "https://artifactory.techno.ingenico.com/artifactory/api/security/token" \
         *    -d "username=yourUserName"</pre>.
         */
        public static final String ANALYZER_ARTIFACTORY_BEARER_TOKEN = "analyzer.artifactory.bearer.token";
        /**
         * The properties key for using the proxy to reach Artifactory.
         */
        public static final String ANALYZER_ARTIFACTORY_USES_PROXY = "analyzer.artifactory.proxy";
        /**
         * The properties key for whether the Artifactory analyzer should use
         * parallel processing.
         */
        public static final String ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS = "analyzer.artifactory.parallel.analysis";
        /**
         * The properties key for whether the Central analyzer is enabled.
         */
        public static final String ANALYZER_CENTRAL_ENABLED = "analyzer.central.enabled";
        /**
         * Key for the URL to obtain content from Maven Central.
         */
        public static final String CENTRAL_CONTENT_URL = "central.content.url";
        /**
         * The properties key for whether the Central analyzer should use
         * parallel processing.
         */
        public static final String ANALYZER_CENTRAL_PARALLEL_ANALYSIS = "analyzer.central.parallel.analysis";
        /**
         * The properties key for whether the Central analyzer should use
         * parallel processing.
         */
        public static final String ANALYZER_CENTRAL_RETRY_COUNT = "analyzer.central.retry.count";
        /**
         * The properties key for whether the OpenSSL analyzer is enabled.
         */
        public static final String ANALYZER_OPENSSL_ENABLED = "analyzer.openssl.enabled";
        /**
         * The properties key for whether the cocoapods analyzer is enabled.
         */
        public static final String ANALYZER_COCOAPODS_ENABLED = "analyzer.cocoapods.enabled";
        /**
         * The properties key for whether the SWIFT package manager analyzer is
         * enabled.
         */
        public static final String ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED = "analyzer.swift.package.manager.enabled";
        /**
         * The properties key for the Central search URL.
         */
        public static final String ANALYZER_CENTRAL_URL = "analyzer.central.url";
        /**
         * The properties key for the Central search query.
         */
        public static final String ANALYZER_CENTRAL_QUERY = "analyzer.central.query";
        /**
         * The properties key for whether Central search results will be cached.
         */
        public static final String ANALYZER_CENTRAL_USE_CACHE = "analyzer.central.use.cache";
        /**
         * The path to dotnet core, if available.
         */
        public static final String ANALYZER_ASSEMBLY_DOTNET_PATH = "analyzer.assembly.dotnet.path";
        /**
         * The path to bundle-audit, if available.
         */
        public static final String ANALYZER_BUNDLE_AUDIT_PATH = "analyzer.bundle.audit.path";
        /**
         * The path to bundle-audit, if available.
         */
        public static final String ANALYZER_BUNDLE_AUDIT_WORKING_DIRECTORY = "analyzer.bundle.audit.working.directory";
        /**
         * The additional configured zip file extensions, if available.
         */
        public static final String ADDITIONAL_ZIP_EXTENSIONS = "extensions.zip";
        /**
         * The key to obtain the path to the VFEED data file.
         */
        public static final String VFEED_DATA_FILE = "vfeed.data_file";
        /**
         * The key to obtain the VFEED connection string.
         */
        public static final String VFEED_CONNECTION_STRING = "vfeed.connection_string";
        /**
         * The key to obtain the base download URL for the VFeed data file.
         */
        public static final String VFEED_DOWNLOAD_URL = "vfeed.download_url";
        /**
         * The key to obtain the download file name for the VFeed data.
         */
        public static final String VFEED_DOWNLOAD_FILE = "vfeed.download_file";
        /**
         * The key to obtain the VFeed update status.
         */
        public static final String VFEED_UPDATE_STATUS = "vfeed.update_status";
        /**
         * The key to the HTTP request method for query last modified date.
         */
        public static final String DOWNLOADER_QUICK_QUERY_TIMESTAMP = "downloader.quick.query.timestamp";
        /**
         * The key to HTTP protocol list to use.
         */
        public static final String DOWNLOADER_TLS_PROTOCOL_LIST = "downloader.tls.protocols";
        /**
         * The key to determine if the CPE analyzer is enabled.
         */
        public static final String ANALYZER_CPE_ENABLED = "analyzer.cpe.enabled";
        /**
         * The key to determine if the CPE Suppression analyzer is enabled.
         */
        public static final String ANALYZER_CPE_SUPPRESSION_ENABLED = "analyzer.cpesuppression.enabled";
        /**
         * The key to determine if the Dependency Bundling analyzer is enabled.
         */
        public static final String ANALYZER_DEPENDENCY_BUNDLING_ENABLED = "analyzer.dependencybundling.enabled";
        /**
         * The key to determine if the Dependency Merging analyzer is enabled.
         */
        public static final String ANALYZER_DEPENDENCY_MERGING_ENABLED = "analyzer.dependencymerging.enabled";
        /**
         * The key to determine if the False Positive analyzer is enabled.
         */
        public static final String ANALYZER_FALSE_POSITIVE_ENABLED = "analyzer.falsepositive.enabled";
        /**
         * The key to determine if the File Name analyzer is enabled.
         */
        public static final String ANALYZER_FILE_NAME_ENABLED = "analyzer.filename.enabled";
        /**
         * The key to determine if the Hint analyzer is enabled.
         */
        public static final String ANALYZER_HINT_ENABLED = "analyzer.hint.enabled";
        /**
         * The key to determine if the Version Filter analyzer is enabled.
         */
        public static final String ANALYZER_VERSION_FILTER_ENABLED = "analyzer.versionfilter.enabled";
        /**
         * The key to determine if the NVD CVE analyzer is enabled.
         */
        public static final String ANALYZER_NVD_CVE_ENABLED = "analyzer.nvdcve.enabled";
        /**
         * The key to determine if the Vulnerability Suppression analyzer is
         * enabled.
         */
        public static final String ANALYZER_VULNERABILITY_SUPPRESSION_ENABLED = "analyzer.vulnerabilitysuppression.enabled";
        /**
         * The key to determine if the NVD CVE updater should be enabled.
         */
        public static final String UPDATE_NVDCVE_ENABLED = "updater.nvdcve.enabled";
        /**
         * The key to determine if dependency-check should check if there is a
         * new version available.
         */
        public static final String UPDATE_VERSION_CHECK_ENABLED = "updater.versioncheck.enabled";
        /**
         * The key to determine which ecosystems should skip the CPE analysis.
         */
        public static final String ECOSYSTEM_SKIP_CPEANALYZER = "ecosystem.skip.cpeanalyzer";
        /**
         * Adds capabilities to batch insert. Tested on PostgreSQL and H2.
         */
        public static final String ENABLE_BATCH_UPDATES = "database.batchinsert.enabled";
        /**
         * Size of database batch inserts.
         */
        public static final String MAX_BATCH_SIZE = "database.batchinsert.maxsize";
        /**
         * The key that specifies the class name of the H2 database shutdown
         * hook.
         */
        public static final String H2DB_SHUTDOWN_HOOK = "data.h2.shutdownhook";
        /**
         * The properties key for whether the Sonatype OSS Index analyzer is
         * enabled.
         */
        public static final String ANALYZER_OSSINDEX_ENABLED = "analyzer.ossindex.enabled";
        /**
         * The properties key for whether the Sonatype OSS Index should use a
         * local cache.
         */
        public static final String ANALYZER_OSSINDEX_USE_CACHE = "analyzer.ossindex.use.cache";
        /**
         * The properties key for the Sonatype OSS Index URL.
         */
        public static final String ANALYZER_OSSINDEX_URL = "analyzer.ossindex.url";
        /**
         * The properties key for the Sonatype OSS Index user.
         */
        public static final String ANALYZER_OSSINDEX_USER = "analyzer.ossindex.user";
        /**
         * The properties key for the Sonatype OSS Index password.
         */
        public static final String ANALYZER_OSSINDEX_PASSWORD = "analyzer.ossindex.password";
        /**
         * The properties key setting whether or not the JSON and XML reports
         * will be pretty printed.
         */
        public static final String PRETTY_PRINT = "odc.reports.pretty.print";
        /**
         * The properties key setting which other keys should be considered
         * sensitive and subsequently masked when logged.
         */
        private static final String MASKED_PROPERTIES = "odc.settings.mask";

        /**
         * private constructor because this is a "utility" class containing
         * constants
         */
        private KEYS() {
            //do nothing
        }
    }
    //</editor-fold>

    /**
     * Initialize the settings object.
     */
    public Settings() {
        initialize(PROPERTIES_FILE);
    }

    /**
     * Initialize the settings object using the given properties.
     *
     * @param properties the properties to be used with this Settings instance
     * @since 4.0.3
     */
    public Settings(final Properties properties) {
        props = properties;
        logProperties("Properties loaded", props);
    }

    /**
     * Initialize the settings object using the given properties file.
     *
     * @param propertiesFilePath the path to the base properties file to load
     */
    public Settings(@NotNull final String propertiesFilePath) {
        initialize(propertiesFilePath);
    }

    /**
     * Initializes the settings object from the given file.
     *
     * @param propertiesFilePath the path to the settings property file
     */
    private void initialize(@NotNull final String propertiesFilePath) {
        props = new Properties();
        try (InputStream in = FileUtils.getResourceAsStream(propertiesFilePath)) {
            props.load(in);
        } catch (NullPointerException ex) {
            LOGGER.error("Did not find settings file '{}'.", propertiesFilePath);
            LOGGER.debug("", ex);
        } catch (IOException ex) {
            LOGGER.error("Unable to load settings from '{}'.", propertiesFilePath);
            LOGGER.debug("", ex);
        }
        logProperties("Properties loaded", props);
    }

    /**
     * Cleans up resources to prevent memory leaks.
     */
    public void cleanup() {
        cleanup(true);
    }

    /**
     * Cleans up resources to prevent memory leaks.
     *
     * @param deleteTemporary flag indicating whether any temporary directories
     * generated should be removed
     */
    public synchronized void cleanup(boolean deleteTemporary) {
        if (deleteTemporary && tempDirectory != null && tempDirectory.exists()) {
            LOGGER.debug("Deleting ALL temporary files from `{}`", tempDirectory.toString());
            FileUtils.delete(tempDirectory);
            tempDirectory = null;
        }
    }

    /**
     * Returns the list of keys to mask.
     *
     * @return the list of keys to mask
     */
    private List<Predicate<String>> getMaskedKeys() {
        String[] masked = getArray(Settings.KEYS.MASKED_PROPERTIES);
        if (masked == null) {
            return new ArrayList<>();
        }
        return Arrays.asList(masked)
                .stream()
                .map(v -> Pattern.compile(v).asPredicate())
                .collect(Collectors.toList());
    }

    /**
     * Check if a given key is considered to have a value with sensitive data.
     *
     * @param key the key to determine if the property should be masked
     * @return <code>true</code> if the key is for a sensitive property value;
     * otherwise <code>false</code>
     */
    private boolean isKeyMasked(@NotNull String key) {
        return getMaskedKeys().stream().anyMatch(maskExp -> maskExp.test(key));
    }

    /**
     * Obtains the printable/loggable value for a given key/value pair. This
     * will mask some values so as to not leak sensitive information.
     *
     * @param key the property key
     * @param value the property value
     * @return the printable value
     */
    protected String getPrintableValue(@NotNull String key, String value) {
        String printableValue = null;
        if (value != null) {
            printableValue = isKeyMasked(key) ? "********" : value;
        }
        return printableValue;
    }

    /**
     * Initializes the masked keys collection. This is done outside of the
     * {@link #initialize(java.lang.String)} method because a caller may use the
     * {@link #mergeProperties(java.io.File)} to add additional properties after
     * the call to initialize.
     */
    protected void initMaskedKeys() {
        maskedKeys = getMaskedKeys();
    }

    /**
     * Logs the properties. This will not log any properties that contain
     * 'password' in the key.
     *
     * @param header the header to print with the log message
     * @param properties the properties to log
     */
    private void logProperties(@NotNull final String header, @NotNull final Properties properties) {
        if (LOGGER.isDebugEnabled()) {
            initMaskedKeys();
            final StringWriter sw = new StringWriter();
            try (PrintWriter pw = new PrintWriter(sw)) {
                pw.format("%s:%n%n", header);
                final Enumeration<?> e = properties.propertyNames();
                while (e.hasMoreElements()) {
                    final String key = (String) e.nextElement();
                    final String value = getPrintableValue(key, properties.getProperty(key));
                    if (value != null) {
                        pw.format("%s='%s'%n", key, value);
                    }
                }
                pw.flush();
                LOGGER.debug(sw.toString());
            }
        }
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setString(@NotNull final String key, @NotNull final String value) {
        props.setProperty(key, value);
        LOGGER.debug("Setting: {}='{}'", key, getPrintableValue(key, value));
    }

    /**
     * Sets a property value only if the value is not null.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setStringIfNotNull(@NotNull final String key, @Nullable final String value) {
        if (null != value) {
            setString(key, value);
        }
    }

    /**
     * Sets a property value only if the value is not null and not empty.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setStringIfNotEmpty(@NotNull final String key, @Nullable final String value) {
        if (null != value && !value.isEmpty()) {
            setString(key, value);
        }
    }

    /**
     * Sets a property value only if the array value is not null and not empty.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setArrayIfNotEmpty(@NotNull final String key, @Nullable final String[] value) {
        if (null != value && value.length > 0) {
            setString(key, new Gson().toJson(value));
        }
    }

    /**
     * Sets a property value only if the array value is not null and not empty.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setArrayIfNotEmpty(@NotNull final String key, @Nullable final List<String> value) {
        if (null != value && !value.isEmpty()) {
            setString(key, new Gson().toJson(value));
        }
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setBoolean(@NotNull final String key, boolean value) {
        setString(key, Boolean.toString(value));
    }

    /**
     * Sets a property value only if the value is not null.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setBooleanIfNotNull(@NotNull final String key, @Nullable final Boolean value) {
        if (null != value) {
            setBoolean(key, value);
        }
    }

    /**
     * Sets a float property value.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setFloat(@NotNull final String key, final float value) {
        setString(key, Float.toString(value));
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setInt(@NotNull final String key, final int value) {
        props.setProperty(key, String.valueOf(value));
        LOGGER.debug("Setting: {}='{}'", key, value);
    }

    /**
     * Sets a property value only if the value is not null.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public void setIntIfNotNull(@NotNull final String key, @Nullable final Integer value) {
        if (null != value) {
            setInt(key, value);
        }
    }

    /**
     * Merges a new properties file into the current properties. This method
     * allows for the loading of a user provided properties file.<br><br>
     * <b>Note</b>: even if using this method - system properties will be loaded
     * before properties loaded from files.
     *
     * @param filePath the path to the properties file to merge.
     * @throws java.io.FileNotFoundException is thrown when the filePath points
     * to a non-existent file
     * @throws java.io.IOException is thrown when there is an exception
     * loading/merging the properties
     */
    @SuppressFBWarnings(justification = "try with resource will clenaup the resources", value = {"OBL_UNSATISFIED_OBLIGATION"})
    public void mergeProperties(@NotNull final File filePath) throws FileNotFoundException, IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            mergeProperties(fis);
        }
    }

    /**
     * Merges a new properties file into the current properties. This method
     * allows for the loading of a user provided properties file.<br><br>
     * Note: even if using this method - system properties will be loaded before
     * properties loaded from files.
     *
     * @param filePath the path to the properties file to merge.
     * @throws java.io.FileNotFoundException is thrown when the filePath points
     * to a non-existent file
     * @throws java.io.IOException is thrown when there is an exception
     * loading/merging the properties
     */
    @SuppressFBWarnings(justification = "try with resource will clenaup the resources", value = {"OBL_UNSATISFIED_OBLIGATION"})
    public void mergeProperties(@NotNull final String filePath) throws FileNotFoundException, IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            mergeProperties(fis);
        }
    }

    /**
     * Merges a new properties file into the current properties. This method
     * allows for the loading of a user provided properties file.<br><br>
     * <b>Note</b>: even if using this method - system properties will be loaded
     * before properties loaded from files.
     *
     * @param stream an Input Stream pointing at a properties file to merge
     * @throws java.io.IOException is thrown when there is an exception
     * loading/merging the properties
     */
    public void mergeProperties(@NotNull final InputStream stream) throws IOException {
        props.load(stream);
        logProperties("Properties updated via merge", props);
    }

    /**
     * Returns a value from the properties file as a File object. If the value
     * was specified as a system property or passed in via the -Dprop=value
     * argument - this method will return the value from the system properties
     * before the values in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file converted to a File object
     */
    @Nullable
    public File getFile(@NotNull final String key) {
        final String file = getString(key);
        if (file == null) {
            return null;
        }
        return new File(file);
    }

    /**
     * Returns a value from the properties file as a File object. If the value
     * was specified as a system property or passed in via the -Dprop=value
     * argument - this method will return the value from the system properties
     * before the values in the contained configuration file.
     * <p>
     * This method will check the configured base directory and will use this as
     * the base of the file path. Additionally, if the base directory begins
     * with a leading "[JAR]\" sequence with the path to the folder containing
     * the JAR file containing this class.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file converted to a File object
     */
    protected File getDataFile(@NotNull final String key) {
        final String file = getString(key);
        LOGGER.debug("Settings.getDataFile() - file: '{}'", file);
        if (file == null) {
            return null;
        }
        if (file.startsWith("[JAR]")) {
            LOGGER.debug("Settings.getDataFile() - transforming filename");
            final File jarPath = getJarPath();
            LOGGER.debug("Settings.getDataFile() - jar file: '{}'", jarPath.toString());
            final File retVal = new File(jarPath, file.substring(6));
            LOGGER.debug("Settings.getDataFile() - returning: '{}'", retVal.toString());
            return retVal;
        }
        return new File(file);
    }

    /**
     * Attempts to retrieve the folder containing the Jar file containing the
     * Settings class.
     *
     * @return a File object
     */
    private File getJarPath() {
        String decodedPath = ".";
        String jarPath = "";
        final ProtectionDomain domain = Settings.class.getProtectionDomain();
        if (domain != null && domain.getCodeSource() != null && domain.getCodeSource().getLocation() != null) {
            jarPath = Settings.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        }
        try {
            decodedPath = URLDecoder.decode(jarPath, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ex) {
            LOGGER.trace("", ex);
        }

        final File path = new File(decodedPath);
        if (path.getName().toLowerCase().endsWith(".jar")) {
            return path.getParentFile();
        } else {
            return new File(".");
        }
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value for the requested property
     * @return the property from the properties file
     */
    public String getString(@NotNull final String key, @Nullable final String defaultValue) {
        return System.getProperty(key, props.getProperty(key, defaultValue));
    }

    /**
     * Returns the temporary directory.
     *
     * @return the temporary directory
     * @throws java.io.IOException if any.
     */
    public synchronized File getTempDirectory() throws IOException {
        if (tempDirectory == null) {
            final File baseTemp = new File(getString(Settings.KEYS.TEMP_DIRECTORY, System.getProperty("java.io.tmpdir")));
            tempDirectory = FileUtils.createTempDirectory(baseTemp);
        }
        return tempDirectory;
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     */
    public String getString(@NotNull final String key) {
        return System.getProperty(key, props.getProperty(key));
    }

    /**
     * Returns a list with the given key.
     * <p>
     * If the property is not set then {@code null} will be returned.
     *
     * @param key the key to get from this
     * {@link org.owasp.dependencycheck.utils.Settings}.
     * @return the list or {@code null} if the key wasn't present.
     */
    public String[] getArray(@NotNull final String key) {
        final String string = getString(key);
        if (string != null) {
            if (string.charAt(0) == '{' || string.charAt(0) == '[') {
                return new Gson().fromJson(string, String[].class);
            } else {
                return string.split(ARRAY_SEP);
            }
        }
        return null;
    }

    /**
     * Removes a property from the local properties collection. This is mainly
     * used in test cases.
     *
     * @param key the property key to remove
     */
    public void removeProperty(@NotNull final String key) {
        props.remove(key);
    }

    /**
     * Returns an int value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws org.owasp.dependencycheck.utils.InvalidSettingException is thrown
     * if there is an error retrieving the setting
     */
    public int getInt(@NotNull final String key) throws InvalidSettingException {
        try {
            return Integer.parseInt(getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
    }

    /**
     * Returns an int value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value to return
     * @return the property from the properties file or the defaultValue if the
     * property does not exist or cannot be converted to an integer
     */
    public int getInt(@NotNull final String key, int defaultValue) {
        int value;
        try {
            value = Integer.parseInt(getString(key));
        } catch (NumberFormatException ex) {
            if (!getString(key, "").isEmpty()) {
                LOGGER.debug("Could not convert property '{}={}' to an int; using {} instead.", key, getPrintableValue(key, getString(key)), defaultValue);
            }
            value = defaultValue;
        }
        return value;
    }

    /**
     * Returns a long value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws org.owasp.dependencycheck.utils.InvalidSettingException is thrown
     * if there is an error retrieving the setting
     */
    public long getLong(@NotNull final String key) throws InvalidSettingException {
        try {
            return Long.parseLong(getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to a long.", ex);
        }
    }

    /**
     * Returns a boolean value from the properties file. If the value was
     * specified as a system property or passed in via the
     * <code>-Dprop=value</code> argument this method will return the value from
     * the system properties before the values in the contained configuration
     * file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws org.owasp.dependencycheck.utils.InvalidSettingException is thrown
     * if there is an error retrieving the setting
     */
    public boolean getBoolean(@NotNull final String key) throws InvalidSettingException {
        return Boolean.parseBoolean(getString(key));
    }

    /**
     * Returns a boolean value from the properties file. If the value was
     * specified as a system property or passed in via the
     * <code>-Dprop=value</code> argument this method will return the value from
     * the system properties before the values in the contained configuration
     * file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value to return if the setting does not
     * exist
     * @return the property from the properties file
     */
    public boolean getBoolean(@NotNull final String key, boolean defaultValue) {
        return Boolean.parseBoolean(getString(key, Boolean.toString(defaultValue)));
    }

    /**
     * Returns a float value from the properties file. If the value was
     * specified as a system property or passed in via the
     * <code>-Dprop=value</code> argument this method will return the value from
     * the system properties before the values in the contained configuration
     * file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value to return if the setting does not
     * exist
     * @return the property from the properties file
     */
    public float getFloat(@NotNull final String key, float defaultValue) {
        float retValue = defaultValue;
        try {
            retValue = Float.parseFloat(getString(key));
        } catch (Throwable ex) {
            LOGGER.trace("ignore", ex);
        }
        return retValue;
    }

    /**
     * Returns a connection string from the configured properties. If the
     * connection string contains a %s, this method will determine the 'data'
     * directory and replace the %s with the path to the data directory. If the
     * data directory does not exist it will be created.
     *
     * @param connectionStringKey the property file key for the connection
     * string
     * @param dbFileNameKey the settings key for the db filename
     * @return the connection string
     * @throws IOException thrown the data directory cannot be created
     * @throws InvalidSettingException thrown if there is an invalid setting
     */
    public String getConnectionString(String connectionStringKey, String dbFileNameKey)
            throws IOException, InvalidSettingException {
        final String connStr = getString(connectionStringKey);
        if (connStr == null) {
            final String msg = String.format("Invalid properties file; %s is missing.", connectionStringKey);
            throw new InvalidSettingException(msg);
        }
        if (connStr.contains("%s")) {
            final File directory = getH2DataDirectory();
            LOGGER.debug("Data directory: {}", directory);
            String fileName = null;
            if (dbFileNameKey != null) {
                fileName = getString(dbFileNameKey);
            }
            if (fileName == null) {
                final String msg = String.format("Invalid properties file to get a file based connection string; '%s' must be defined.",
                        dbFileNameKey);
                throw new InvalidSettingException(msg);
            }
            if (connStr.startsWith("jdbc:h2:file:") && fileName.endsWith(".mv.db")) {
                fileName = fileName.substring(0, fileName.length() - 6);
            }
            // yes, for H2 this path won't actually exists - but this is sufficient to get the value needed
            final File dbFile = new File(directory, fileName);
            final String cString = String.format(connStr, dbFile.getCanonicalPath());
            LOGGER.debug("Connection String: '{}'", cString);
            return cString;
        }
        return connStr;
    }

    /**
     * Retrieves the primary data directory that is used for caching web
     * content.
     *
     * @return the data directory to store data files
     * @throws java.io.IOException is thrown if an java.io.IOException occurs of
     * course...
     */
    public File getDataDirectory() throws IOException {
        final File path = getDataFile(Settings.KEYS.DATA_DIRECTORY);
        if (path != null && (path.exists() || path.mkdirs())) {
            return path;
        }
        throw new IOException(String.format("Unable to create the data directory '%s'",
                (path == null) ? "unknown" : path.getAbsolutePath()));
    }

    /**
     * Retrieves the H2 data directory - if the database has been moved to the
     * temp directory this method will return the temp directory.
     *
     * @return the data directory to store data files
     * @throws java.io.IOException is thrown if an java.io.IOException occurs of
     * course...
     */
    public File getH2DataDirectory() throws IOException {
        final String h2Test = getString(Settings.KEYS.H2_DATA_DIRECTORY);
        final File path;
        if (h2Test != null && !h2Test.isEmpty()) {
            path = getDataFile(Settings.KEYS.H2_DATA_DIRECTORY);
        } else {
            path = getDataFile(Settings.KEYS.DATA_DIRECTORY);
        }
        if (path != null && (path.exists() || path.mkdirs())) {
            return path;
        }
        throw new IOException(String.format("Unable to create the h2 data directory '%s'",
                (path == null) ? "unknown" : path.getAbsolutePath()));
    }

    /**
     * Generates a new temporary file name that is guaranteed to be unique.
     *
     * @param prefix the prefix for the file name to generate
     * @param extension the extension of the generated file name
     * @return a temporary File
     * @throws java.io.IOException if any.
     */
    public File getTempFile(@NotNull final String prefix, @NotNull final String extension) throws IOException {
        final File dir = getTempDirectory();
        final String tempFileName = String.format("%s%s.%s", prefix, UUID.randomUUID().toString(), extension);
        final File tempFile = new File(dir, tempFileName);
        if (tempFile.exists()) {
            return getTempFile(prefix, extension);
        }
        return tempFile;
    }
}
