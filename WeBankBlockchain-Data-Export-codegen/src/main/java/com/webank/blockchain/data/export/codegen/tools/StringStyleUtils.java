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

import java.util.PrimitiveIterator.OfInt;
import java.util.stream.IntStream;

import javax.annotation.PostConstruct;

import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.webank.blockchain.data.export.codegen.enums.NameStyleEnum;

/**
 * StringStyleUtils
 *
 * @Description: StringStyleUtils
 * @author maojiayu
 * @data Dec 28, 2018 4:11:29 PM
 *
 */
@Component
public class StringStyleUtils {

    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;

    private static String nameStyle;

    @SuppressWarnings("static-access")
    @PostConstruct
    public void init() {
        this.nameStyle = systemEnvironmentConfig.getNameStyle();
    }

    /**
     * Camel -> underline e.g. aBc -> a_bc
     * 
     * @param str
     * @return
     */
    public static String upper2underline(String str) {
        if (nameStyle.equalsIgnoreCase(NameStyleEnum.RAW_CASE.getStyle())) {
            return str;
        }
        if (str.length() == 1) {
            return str.toLowerCase();
        }
        StringBuilder sb = new StringBuilder();
        str.chars().forEach(c -> {
            char cc = (char) c;
            if (cc >= 'A' && cc <= 'Z') {
                sb.append("_").append((char) (cc + 32)); // 32 = 'a' - 'A'
            } else {
                sb.append(cc);
            }
        });
        if (sb.indexOf("_") == 0) {
            sb.deleteCharAt(0);
        }
        String r = sb.toString();
        return r.replaceAll("__", "_");
    }

    /**
     * underline -> camel e.g. __a_bc_d__e_ -> _ABcD_E_
     * 
     * @param str
     * @return
     */
    public static String underline2upper(String str) {
        StringBuilder sb = new StringBuilder();
        boolean mode = false;
        IntStream intStream = str.chars();
        OfInt iterator = intStream.iterator();
        while (iterator.hasNext()) {
            int c = iterator.nextInt();
            char cc = (char) c;
            if (mode) {
                if (cc >= 'a' && cc <= 'z') {
                    sb.append(((char) (cc - 32)));
                    mode = false;
                    continue;
                }
                if (cc == '_') {
                    sb.append('_');
                    continue;
                }
                sb.append((char) cc);
                mode = false;
            } else {
                if (cc == '_') {
                    mode = true;
                } else {
                    sb.append((char) cc);
                }
            }
        }
        if (mode) {
            sb.append('_');
        }
        return sb.toString();
    }
}
