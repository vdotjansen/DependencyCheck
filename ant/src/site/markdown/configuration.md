Configuration
====================
Once dependency-check-ant has been [installed](index.html) the defined tasks can be used.

* dependency-check - the primary task used to check the project dependencies. Configuration options are below.
* dependency-check-purge - deletes the local copy of the NVD; this should rarely be used (if ever). See the [purge configuration](config-purge.html) for more information.
* dependency-check-update - downloads and updates the local copy of the NVD. See the [update configuration](config-update.html) for more information.

To configure the dependency-check task you can add it to a target and include a
file based [resource collection](http://ant.apache.org/manual/Types/resources.html#collection)
such as a [FileSet](http://ant.apache.org/manual/Types/fileset.html), [DirSet](http://ant.apache.org/manual/Types/dirset.html),
or [FileList](http://ant.apache.org/manual/Types/filelist.html) that includes
the project's dependencies.

```xml
<target name="dependency-check" description="Dependency-Check Analysis">
    <dependency-check projectname="Hello World"
                      reportoutputdirectory="${basedir}"
                      reportformat="ALL">
        <suppressionfile path="${basedir}/path/to/suppression.xml" />
        <retirejsFilter regex="copyright.*jeremy long" />
        <fileset dir="lib">
            <include name="**/*.jar"/>
        </fileset>
    </dependency-check>
</target>
```

Configuration: dependency-check Task
--------------------
The following properties can be set on the dependency-check task.

Property              | Description                                                                                                                                                                                                    | Default Value
----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------
autoUpdate            | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false.                                                                                             | true
cveValidForHours      | Sets the number of hours to wait before checking for new updates from the NVD                                                                                                                                  | 4
failOnError           | Whether the build should fail if there is an error executing the dependency-check analysis                                                                                                                     | true
failBuildOnCVSS       | Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail. | 11
junitFailOnCVSS       | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.                                                                                               | 0
prettyPrint           | Whether the XML and JSON formatted reports should be pretty printed.                                                                                                                                           | false
projectName           | The name of the project being scanned.                                                                                                                                                                         | Dependency-Check
reportFormat          | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, ALL).                                                                                                                                          | HTML
reportOutputDirectory | The location to write the report(s). Note, this is not used if generating the report as part of a `mvn site` build                                                                                             | 'target'
hintsFile             | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html)                                                                                                                | &nbsp;
proxyServer           | The Proxy Server; see the [proxy configuration](../data/proxy.html) page for more information.                                                                                                                 | &nbsp;
proxyPort             | The Proxy Port.                                                                                                                                                                                                | &nbsp;
proxyUsername         | Defines the proxy user name.                                                                                                                                                                                   | &nbsp;
proxyPassword         | Defines the proxy password.                                                                                                                                                                                    | &nbsp; 
nonProxyHosts         | Defines the hosts that will not be proxied.                                                                                                                                                                    | &nbsp;
connectionTimeout     | The URL Connection Timeout.                                                                                                                                                                                    | &nbsp;
enableExperimental    | Enable the [experimental analyzers](../analyzers/index.html). If not enabled the experimental analyzers (see below) will not be loaded or used.                                                                | false
enableRetired         | Enable the [retired analyzers](../analyzers/index.html). If not enabled the retired analyzers (see below) will not be loaded or used.                                                                          | false
suppressionFile       | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html). The parameter value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
junitFailOnCVSS       | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.                                                                                               | 0

The following nested elements can be set on the dependency-check task.

Element           | Property | Description                                                                                                                                                                                        | Default Value
------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------
suppressionFile   | path     | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html). Element can be specified multiple times. The parameter value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;| &nbsp;
reportFormat      | format   | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, ALL). Element can be specified multiple times.                                                                                     | &nbsp;


Analyzer Configuration
====================
The following properties are used to configure the various file type analyzers.
These properties can be used to turn off specific analyzers if it is not needed.
Note, that specific analyzers will automatically disable themselves if no file
types that they support are detected - so specifically disabling them may not
be needed.

Property                            | Description                                                                                                | Default Value
------------------------------------|------------------------------------------------------------------------------------------------------------|------------------
archiveAnalyzerEnabled              | Sets whether the Archive Analyzer will be used.                                                            | true
zipExtensions                       | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
jarAnalyzer                         | Sets whether the Jar Analyzer will be used.                                                                | true
centralAnalyzerEnabled              | Sets whether the Central Analyzer will be used. **Disabling this analyzer for Ant builds is not recommended as it could lead to false negatives (e.g. libraries that have vulnerabilities may not be reported correctly).** If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below).                                  | true
centralAnalyzerUseCache             | Sets whether the Central Analyer will cache results. Cached results expire after 30 days.                  | true
ossIndexAnalyzerEnabled             | Sets whether the [OSS Index Analyzer](../analyzers/oss-index-analyzer.html) will be enabled. This analyzer requires an internet connection. | true
ossindexAnalyzerUseCache            | Sets whether the OSS Index Analyzer will cache results. Cached results expire after 24 hours.              | true
ossindexAnalyzerUsername            | Sets the username for OSS Index - note an account with OSS Index is not required.                          | &nbsp;
ossindexAnalyzerPassword            | Sets the password for OSS Index.                                                                           | &nbsp;
nexusAnalyzerEnabled                | Sets whether Nexus Analyzer will be used (requires Nexus Pro). This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
nexusUrl                            | Defines the Nexus web service endpoint (example http://domain.enterprise/nexus/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
nexusUser                           | The username to authenticate to the Nexus Server's web service end point. If not set the Nexus Analyzer will use an unauthenticated connection. | &nbsp;
nexusPassword                       | The password to authenticate to the Nexus Server's web service end point. If not set the Nexus Analyzer will use an unauthenticated connection. | &nbsp;
nexusUsesProxy                      | Whether or not the defined proxy should be used when connecting to Nexus.                                  | true
artifactoryAnalyzerEnabled          | Sets whether Artifactory analyzer will be used                                                             | false
artifactoryAnalyzerUrl              | The Artifactory server URL.                                                                                | &nbsp;
artifactoryAnalyzerUseProxy         | Whether Artifactory should be accessed through a proxy or not.                                             | false
artifactoryAnalyzerParallelAnalysis | Whether the Artifactory analyzer should be run in parallel or not                                          | true
artifactoryAnalyzerUsername         | The user name (only used with API token) to connect to Artifactory instance                                | &nbsp;
artifactoryAnalyzerApiToken         | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp;
artifactoryAnalyzerBearerToken      | The bearer token to connect to Artifactory instance                                                        | &nbsp;
pyDistributionAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used.        | true
pyPackageAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used.             | true
rubygemsAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used.               | true
opensslAnalyzerEnabled              | Sets whether the openssl Analyzer should be used.                                                          | true
cmakeAnalyzerEnabled                | Sets whether the [experimental](../analyzers/index.html) CMake Analyzer should be used.                    | true
autoconfAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) autoconf Analyzer should be used.                 | true
composerAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used.   | true
nodeAnalyzerEnabled                 | Sets whether the [retired](../analyzers/index.html) Node.js Analyzer should be used.                       | true
nodeAuditAnalyzerEnabled            | Sets whether the Node Audit Analyzer should be used. This analyzer requires an internet connection.        | true
nodeAuditAnalyzerUseCache           | Sets whether the Node Audit Analyzer will cache results. Cached results expire after 24 hours.             | true
nodeAuditSkipDevDependencies        | Sets whether the Node Audit Analyzer will skip devDependencies.                                            | false
retireJsAnalyzerEnabled             | Sets whether the RetireJS Analyzer should be used.                                                         | true
retirejsForceupdate                 | Sets whether the RetireJS Analyzer should update regardless of the `autoupdate` setting.                   | false
retirejsFilterNonVulnerable         | Configures the RetireJS Analyzer to remove non-vulnerable JS dependencies from the report.                 | false
retirejsFilter                      | A nested configuration that can be specified multple times; The regex defined is used to filter JS files based on content. | &nbsp;
retireJsUrl                         | The URL to the Retire JS repository.                                                                       | https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json
nuspecAnalyzerEnabled               | Sets whether the .NET Nuget Nuspec Analyzer will be used.                                                  | true
nugetconfAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) .NET Nuget packages.config Analyzer will be used. | true
cocoapodsAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) Cocoapods Analyzer should be used.                | true
bundleAuditAnalyzerEnabled          | Sets whether the [experimental](../analyzers/index.html) Bundle Audit Analyzer should be used.             | true
bundleAuditPath                     | Sets the path to the bundle audit executable; only used if bundle audit analyzer is enabled and experimental analyzers are enabled.  | &nbsp;
swiftPackageManagerAnalyzerEnabled  | Sets whether the [experimental](../analyzers/index.html) Switft Package Analyzer should be used.           | true
assemblyAnalyzerEnabled             | Sets whether the .NET Assembly Analyzer should be used.                                                    | true
pathToCore                          | The path to dotnet core .NET assembly analysis on non-windows systems.                                     | &nbsp;
golangDepEnabled                    | Sets whether or not the [experimental](../analyzers/index.html) Golang Dependency Analyzer should be used. | true
golangModEnabled                    | Sets whether or not the [experimental](../analyzers/index.html) Goland Module Analyzer should be used; requires `go` to be installed. | true
pathToGo                            | The path to `go`.                                                                                          | &nbsp;

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.

Property             | Description                                                              | Default Value
---------------------|--------------------------------------------------------------------------|------------------
cveUrl12Modified     | URL for the modified CVE 1.2.                                            | http://nvd.nist.gov/download/nvdcve-modified.xml
cveUrl20Modified     | URL for the modified CVE 2.0.                                            | http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml
cveUrl12Base         | Base URL for each year's CVE 1.2, the %d will be replaced with the year. | http://nvd.nist.gov/download/nvdcve-%d.xml
cveUrl20Base         | Base URL for each year's CVE 2.0, the %d will be replaced with the year. | http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml
dataDirectory        | Data directory that is used to store the local copy of the NVD. This should generally not be changed. | data
databaseDriverName   | The name of the database driver. Example: org.h2.Driver.                 | &nbsp;
databaseDriverPath   | The path to the database driver JAR file; only used if the driver is not in the class path. | &nbsp;
connectionString     | The connection string used to connect to the database. See using a [database server](../data/database.html). | &nbsp;
databaseUser         | The username used when connecting to the database.                       | &nbsp;
databasePassword     | The password used when connecting to the database.                       | &nbsp;
