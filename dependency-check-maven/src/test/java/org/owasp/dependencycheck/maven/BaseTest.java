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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.io.IOException;
import java.io.InputStream;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long
 */
public class BaseTest {

    /**
     * The properties file location.
     */
    public static final String PROPERTIES_FILE = "mojo.properties";

    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * Initialize the {@link Settings}.
     */
    @Before
    public void setUp() throws IOException {
        settings = new Settings();
        try (InputStream mojoProperties = BaseTest.class.getClassLoader().getResourceAsStream(BaseTest.PROPERTIES_FILE)) {
            settings.mergeProperties(mojoProperties);
        }
    }

    /**
     * Clean the {@link Settings}.
     */
    @After
    public void tearDown() {
        settings.cleanup(true);
    }

    /**
     * Returns the settings for the test cases.
     *
     * @return
     */
    protected Settings getSettings() {
        return settings;
    }
}
