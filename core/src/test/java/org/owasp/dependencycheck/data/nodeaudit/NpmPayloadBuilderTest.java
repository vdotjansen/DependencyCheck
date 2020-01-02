/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import org.owasp.dependencycheck.BaseTest;

public class NpmPayloadBuilderTest {

    @Test
    public void testSanitizer() {
        JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("name", "my app")
                .add("version", "1.0.0")
                .add("random", "random")
                .add("lockfileVersion", 1)
                .add("requires", true)
                .add("dependencies",
                        Json.createObjectBuilder().add("abbrev",
                                Json.createObjectBuilder()
                                        .add("version", "1.1.1")
                                        .add("resolved", "https://registry.npmjs.org/abbrev/-/abbrev-1.1.1.tgz")
                                        .add("integrity", "sha512-nne9/IiQ/hzIhY6pdDnbBtz7DjPTKrY00P/zvPSm5pOFkl6xuGrGnXn/VtTNNfNtAfZ9/1RtehkszU9qcTii0Q==")
                                        .add("dev", true)
                        )
                );

        JsonObject packageJson = builder.build();
        Map<String, String> dependencyMap = new HashMap<>();
        JsonObject sanitized = NpmPayloadBuilder.build(packageJson, dependencyMap);

        Assert.assertTrue(sanitized.containsKey("name"));
        Assert.assertTrue(sanitized.containsKey("version"));
        Assert.assertTrue(sanitized.containsKey("dependencies"));
        Assert.assertTrue(sanitized.containsKey("requires"));

        JsonObject requires = sanitized.getJsonObject("requires");
        Assert.assertTrue(requires.containsKey("abbrev"));
        Assert.assertEquals("^1.1.1", requires.getString("abbrev"));

        Assert.assertFalse(sanitized.containsKey("lockfileVersion"));
        Assert.assertFalse(sanitized.containsKey("random"));
    }

    @Test
    public void testSanitizePackage() {
        InputStream in = BaseTest.getResourceAsStream(this, "nodeaudit/package-lock.json");
        Map<String, String> dependencyMap = new HashMap<>();
        try (JsonReader jsonReader = Json.createReader(in)) {
            JsonObject packageJson = jsonReader.readObject();
            JsonObject sanitized = NpmPayloadBuilder.build(packageJson, dependencyMap);

            Assert.assertTrue(sanitized.containsKey("name"));
            Assert.assertTrue(sanitized.containsKey("version"));
            Assert.assertTrue(sanitized.containsKey("dependencies"));
            Assert.assertTrue(sanitized.containsKey("requires"));

            JsonObject requires = sanitized.getJsonObject("requires");
            Assert.assertTrue(requires.containsKey("bcrypt-nodejs"));
            Assert.assertEquals("^0.0.3", requires.getString("bcrypt-nodejs"));

            Assert.assertFalse(sanitized.containsKey("lockfileVersion"));
            Assert.assertFalse(sanitized.containsKey("random"));
        }
    }
}
