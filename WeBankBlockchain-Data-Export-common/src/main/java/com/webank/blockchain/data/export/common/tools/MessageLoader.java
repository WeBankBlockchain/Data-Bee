/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.common.tools;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import lombok.extern.slf4j.Slf4j;


/**
 * Load error messages defined in config.
 *
 * @author maojiayu
 * @data Dec 28, 2018 5:17:30 PM
 *
 */
@Slf4j
public class MessageLoader {
    private static Properties properties = new Properties();

    static {
        InputStream is = MessageLoader.class.getClassLoader().getResourceAsStream("error.properties");
        if (is != null) {
            try {
                properties.load(is);
            } catch (IOException e) {
                log.error("", e);
                throw new RuntimeException(e);
            }
        } else {
            throw new RuntimeException("error.properties not found");
        }
    }

    public static String getMessage(String name) {
        return properties.getProperty(name, null);
    }

    public static String getMessage(String name, Object...args) {
        String template = properties.getProperty(name, null);
        return String.format(template, args);
    }
}
