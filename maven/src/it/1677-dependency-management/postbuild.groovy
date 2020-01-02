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

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import java.nio.charset.Charset;


// Check to see if jackson-dataformat-xml-2.4.5.jar was identified.
//TODO change this to xpath and check for CVE-2016-3720
String log = FileUtils.readFileToString(new File(basedir, "target/dependency-check-report.xml"), Charset.defaultCharset().name());
int count = StringUtils.countMatches(log, "<name>CVE-2016-7051</name>");
if (count == 0){
    System.out.println(String.format("jackson-dataformat-xml (CVE-2016-7051) was not identified", count));
    return false;
}
return true;
