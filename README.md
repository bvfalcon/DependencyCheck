Dependency-Check: goal analyze
==================

How to use analyze goal.

Preconditions:

1. [Java 11](https://www.oracle.com/java/technologies/downloads/#java11) or higher is installed
2. [Maven 3.6](https://maven.apache.org/download.cgi) or higher is installed


Steps:

1. Build the plugin with command

```
mvn clean install -DskipTests
```

2. Create new folder and file pom.xml in it with content>

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>test</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</project> 
```


3. In this folder run analysis with command

```
mvn clean org.owasp:dependency-check-maven:6.5.2.test:analyze -DgroupId=<groupId> -DartifactId=<artifactId>
```

Examples:

```
mvn clean org.owasp:dependency-check-maven:6.5.2.test:analyze -DgroupId=org.glassfish -DartifactId=jakarta.faces
mvn clean org.owasp:dependency-check-maven:6.5.2.test:analyze -DgroupId=org.springframework -DartifactId=spring-web
mvn clean org.owasp:dependency-check-maven:6.5.2.test:analyze -DgroupId=com.fasterxml.jackson.core -DartifactId=jackson-databind
```
And wait. On analysis complete, in folder target/ can be seen one or more files "dependency-analyze-report-*.html" and one file dependency-analyze-report-result.csv.
File dependency-analyze-report-result.csv contains final results of analysis.

License
-------

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE.txt](https://raw.githubusercontent.com/jeremylong/DependencyCheck/master/LICENSE.txt) file for the full license.

Dependency-Check makes use of several other open source libraries. Please see the [NOTICE.txt][notices] file for more information.

Copyright (c) 2012-2021 Jeremy Long. All Rights Reserved.

  [wiki]: https://github.com/jeremylong/DependencyCheck/wiki
  [notices]: https://github.com/jeremylong/DependencyCheck/blob/master/NOTICE.txt
