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
package com.webank.blockchain.data.export.common.bo.contract;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * FieldVO stores one single field of a contract field.
 *
 * @author maojiayu
 * @data Dec 28, 2018 5:06:04 PM
 *
 */
@Data
@Accessors(chain = true)
public class FieldVO {
    private String sqlName;
    private String solidityName;
    private String javaName;
    private String sqlType;
    private String solidityType;
    private String javaType;
    private String javaCapName; // 首字母大写
    private String typeMethod; // 转化方法

}
