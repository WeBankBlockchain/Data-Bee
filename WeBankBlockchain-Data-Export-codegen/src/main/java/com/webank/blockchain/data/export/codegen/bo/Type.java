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
package com.webank.blockchain.data.export.codegen.bo;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import lombok.Data;

/**
 * Type
 *
 * @Description: Type
 * @author maojiayu
 * @data Apr 27, 2020 2:49:09 PM
 *
 */
@Data
public class Type {
    private List<String> actualTypeArguments;
    private String rawType;
    private String ownerType;
    private String typeName;

    public int getArgType() {
        String arg = actualTypeArguments.get(0);
        if (StringUtils.containsIgnoreCase(arg, "int")) {
            // numeric
            return 1;
        } else if (StringUtils.containsIgnoreCase(arg, "byte")) {
            // bytes
            return 2;
        } else if (StringUtils.containsIgnoreCase(arg, "address")) {
            // address
            return 3;
        } else if (StringUtils.containsIgnoreCase(arg, "bool")) {
            // bool
            return 4;
        } else {
            return 0;
        }
    }
}
