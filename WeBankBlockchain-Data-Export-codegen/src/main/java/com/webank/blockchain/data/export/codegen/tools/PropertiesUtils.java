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
package com.webank.blockchain.data.export.codegen.tools;

import java.io.IOException;
import java.util.Iterator;
import java.util.Properties;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import cn.hutool.core.io.resource.ClassPathResource;
import cn.hutool.core.util.StrUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * PropertiesUtils
 *
 * @Description: PropertiesUtils
 * @author maojiayu
 * @data Dec 28, 2018 4:10:49 PM
 *
 */
@Slf4j
@Component
public class PropertiesUtils {

    @Autowired
    private ClassPathResource autoResource;

    private static ClassPathResource resource;

    @PostConstruct
    private void init() {
        resource = this.autoResource;
    }

    /**
     * return the first mapping result of args.
     *
     * 
     * @param property key
     * @return property value
     */
    public static String getProperty(String...args) {
        Properties properties = new Properties();
        try {
            properties.load(resource.getStream());
            for (String key : args) {
                Iterator ite = properties.keySet().iterator();
                while (ite.hasNext()) {
                    String s = (String) ite.next();
                    if (key.equalsIgnoreCase(s)) {
                        return properties.getProperty(s);
                    }
                }
            }
        } catch (IOException e) {
            log.error("getProperty error {}", e.getMessage());
        }
        return args[args.length - 1];
    }

    /**
     * get the very specific value of settings. If the field is not set, then return the default value.
     * 
     * @param contractName
     * @param eventName
     * @param feature
     * @param defaultValue
     * @return
     */
    public static String getGlobalProperty(String type, String contractName, String eventName, String feature,
            String defaultValue) {
        String template = "{}.{}.{}";
        String eventTemplate = "{}.{}.{}.{}";
        String eventConfig = StrUtil.format(eventTemplate, type, contractName, eventName, feature);
        String contractConfig = StrUtil.format(template, type, contractName, feature);
        String defaultConfig = StrUtil.format(template, type, "default", feature);
        return PropertiesUtils.getProperty(eventConfig, contractConfig, defaultConfig, defaultValue);
    }

    /**
     * get the very specific value of settings without a default value.
     * 
     * return the specific config value, eg. return event property prefer to contract value.
     * 
     * @param contractName
     * @param eventName
     * @param feature
     * @return
     */
    public static String getPropertyWithoutDefault(String type, String contractName, String eventName, String feature) {
        String contractTemplate = "{}.{}.{}";
        String eventTemplate = "{}.{}.{}.{}";
        String eventConfig = StrUtil.format(eventTemplate, type, contractName, eventName, feature);
        String contractConfig = StrUtil.format(contractTemplate, type, contractName, feature);
        return PropertiesUtils.getProperty(eventConfig, contractConfig);
    }

}
