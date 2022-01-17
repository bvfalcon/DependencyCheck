/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import static org.apache.commons.lang3.StringUtils.CR;
import static org.apache.commons.lang3.StringUtils.LF;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.reporting.ReportGenerator;

import com.google.common.collect.Sets;

@Mojo(
        name = "analyze",
        defaultPhase = LifecyclePhase.VERIFY,
        threadSafe = true,
        requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
        requiresOnline = true
)
public class AnalyzeDependencyMojo extends BaseDependencyCheckMojo {

    @Override
    public boolean canGenerateReport() {
        populateSettings();
        boolean isCapable = false;
        for (Artifact a : getProject().getArtifacts()) {
            if (!getArtifactScopeExcluded().passes(a.getScope())) {
                isCapable = true;
                break;
            }
        }
        return isCapable;
    }

    @Override
    public String getName(Locale locale) {
        return "dependency-analyze";
    }

    @Override
    public String getDescription(Locale locale) {
        return "Generates a report providing details on any published vulnerabilities within dependency.";
    }

    private String groupId;
    private String artifactId;
    private String version;

    @Override
    protected void runCheck() throws MojoExecutionException, MojoFailureException {
        groupId = System.getProperty("groupId");
        artifactId = System.getProperty("artifactId");
        try {
            List<String> versions = getAvailableVersions(groupId, artifactId);
            versions.forEach(version -> {
                this.version = version;
                try {
                    super.runCheck();
                } catch (MojoExecutionException | MojoFailureException e) {
                    getLog().error("Error " + e.getMessage() + " has acquired while version " + version + " analysing.", e);
                }
            });
            writeResults(versions);
        } catch (IOException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }
    }

    @Override
    protected ExceptionCollection scanDependencies(final Engine engine) throws MojoExecutionException {
        MavenProject project = getProject();
        project.setVersion(version);

        Artifact artifact = new DefaultArtifact(groupId, artifactId, version, "compile", "jar", null, new DefaultArtifactHandler("jar"));
        project.setDependencyArtifacts(Sets.newHashSet(artifact));

        Dependency dependency = new Dependency();
        dependency.setGroupId(groupId);
        dependency.setArtifactId(artifactId);
        dependency.setVersion(version);
        dependency.setScope("compile");
        project.setDependencies(Arrays.asList(dependency));

        return scanArtifacts(project, engine, true);
    }

    private List<String> getAvailableVersions(String groupId, String artifactId) throws MalformedURLException, IOException {
        String out = new Scanner(new URL("https://repo1.maven.org/maven2/" + groupId.replaceAll("\\.", "/") + "/" + artifactId + "/maven-metadata.xml").openStream(), StandardCharsets.UTF_8.name()).useDelimiter("\\A").next();
        String[] versions = StringUtils.substringsBetween(out, "<version>", "</version>");
        return Arrays.asList(versions);
    }

    private void writeResults(List<String> versions) throws IOException {
        StringBuilder sb = new StringBuilder("\"VERSION\",\"LOW\",\"MEDIUM\",\"HIGH\",\"CRITICAL\"").append(CR).append(LF);
        versions.forEach(itemVersion -> {
            File file = new File(this.getOutputDirectory(), ReportGenerator.ANALYSE_PREFIX + itemVersion + ".html");
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                IOUtils.copy(file, baos);
                String content = new String(baos.toByteArray(), StandardCharsets.UTF_8.name());
                int low = StringUtils.countMatches(content, "CVSSv3:<ul><li>Base Score: LOW");
                int medium = StringUtils.countMatches(content, "CVSSv3:<ul><li>Base Score: MEDIUM");
                int high = StringUtils.countMatches(content, "CVSSv3:<ul><li>Base Score: HIGH");
                int critical = StringUtils.countMatches(content, "CVSSv3:<ul><li>Base Score: CRITICAL");
                sb
                    .append("\"").append(itemVersion).append("\"").append(",")
                    .append("\"").append(low).append("\"").append(",")
                    .append("\"").append(medium).append("\"").append(",")
                    .append("\"").append(high).append("\"").append(",")
                    .append("\"").append(critical).append("\"")
                    .append(CR).append(LF);
            } catch (IOException e) {
                getLog().error("Problem reading file " + file.getAbsolutePath(), e);
            }
        });
        FileUtils.write(new File(this.getOutputDirectory(), ReportGenerator.ANALYSE_PREFIX + "result.csv"), sb, StandardCharsets.UTF_8.name());
    }
}