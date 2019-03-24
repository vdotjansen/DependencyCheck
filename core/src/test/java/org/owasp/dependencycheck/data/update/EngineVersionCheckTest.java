/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.data.update;

import com.google.common.base.Splitter;
import java.util.List;
import java.util.Properties;
import mockit.Injectable;
import mockit.Mock;
import mockit.MockUp;
import mockit.Tested;

import org.joda.time.DateTime;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DependencyVersion;

/**
 *
 * @author Jeremy Long
 */
public class EngineVersionCheckTest extends BaseTest {

    @Injectable
    private CveDB cveDb;
    @Tested
    private DatabaseProperties dbProperties;

    /**
     * Test of shouldUpdate method, of class EngineVersionCheck.
     */
    @Test
    public void testShouldUpdate() throws Exception {
        new MockUp<DatabaseProperties>() {
            private final Properties properties = new Properties();

            @Mock
            public void $init(CveDB db) {
                //empty
            }

            @Mock
            public void save(String key, String value) throws UpdateException {
                properties.setProperty(key, value);
            }

            @Mock
            public String getProperty(String key) {
                return properties.getProperty(key);
            }
        };

        String updateToVersion = "1.2.6";
        String currentVersion = "1.2.6";

        long lastChecked = dateToMilliseconds("2014-12-01");
        long now = dateToMilliseconds("2014-12-01");

        EngineVersionCheck instance = new EngineVersionCheck(getSettings());
        boolean expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        boolean result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.5";
        currentVersion = "1.2.5";
        lastChecked = dateToMilliseconds("2014-10-01");
        now = dateToMilliseconds("2014-12-01");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);
        //System.out.println(properties.getProperty(CURRENT_ENGINE_RELEASE));

        updateToVersion = "1.2.5";
        currentVersion = "1.2.5";
        lastChecked = dateToMilliseconds("2014-12-01");
        now = dateToMilliseconds("2014-12-03");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.6";
        currentVersion = "1.2.5";
        lastChecked = dateToMilliseconds("2014-12-01");
        now = dateToMilliseconds("2014-12-03");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.5";
        currentVersion = "1.2.6";
        lastChecked = dateToMilliseconds("2014-12-01");
        now = dateToMilliseconds("2014-12-08");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "";
        currentVersion = "1.2.5";
        lastChecked = dateToMilliseconds("2014-12-01");
        now = dateToMilliseconds("2014-12-03");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "";
        currentVersion = "1.2.5";
        lastChecked = dateToMilliseconds("2014-12-01");
        now = dateToMilliseconds("2015-12-08");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);
    }

    /**
     * Test of getCurrentReleaseVersion method, of class EngineVersionCheck.
     */
    @Test
    public void testGetCurrentReleaseVersion() {
        EngineVersionCheck instance = new EngineVersionCheck(getSettings());
        DependencyVersion minExpResult = new DependencyVersion("1.2.6");
        String release = instance.getCurrentReleaseVersion();
        DependencyVersion result = new DependencyVersion(release);
        assertTrue(minExpResult.compareTo(result) <= 0);
    }

    /**
     * Converts a date in the form of yyyy-MM-dd into the epoch milliseconds.
     *
     * @param date a date in the format of yyyy-MM-dd
     * @return milliseconds
     */
    private long dateToMilliseconds(String date) {
        //removed for compatibility with joda-time 1.6
        //DateTimeFormatter dtf = DateTimeFormat.forPattern("yyyy-MM-dd");
        //return DateTime.parse(date, dtf).toInstant().getMillis();
        List<String> dp = Splitter.on('-').splitToList(date);
        int y = Integer.parseInt(dp.get(0));
        int m = Integer.parseInt(dp.get(1));
        int d = Integer.parseInt(dp.get(2));
        DateTime dt = new DateTime(y, m, d, 0, 0, 0, 0);
        return dt.toInstant().getMillis();
    }

}
