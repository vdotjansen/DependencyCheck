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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.hamcrest.Matchers;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long
 */
public class SeverityUtilTest {

    /**
     * Test of estimateCvssV2 method, of class SeverityUtil.
     */
    @Test
    public void testEstimateCvssV2() {
        String severity = null;
        float expResult = 3.9F;
        float result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "garbage";
        expResult = 3.9F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "Critical";
        expResult = 10.0F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "HIGH";
        expResult = 10.0F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "moderate";
        expResult = 6.9F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "medium";
        expResult = 6.9F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "info";
        expResult = 0.0F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "informational";
        expResult = 0.0F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "low";
        expResult = 3.9F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "unknown";
        expResult = 3.9F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));

        severity = "none";
        expResult = 3.9F;
        result = SeverityUtil.estimateCvssV2(severity);
        assertThat(String.format("Expected %s to be %f", severity, expResult),
                result, Matchers.equalTo(expResult));
    }

}
