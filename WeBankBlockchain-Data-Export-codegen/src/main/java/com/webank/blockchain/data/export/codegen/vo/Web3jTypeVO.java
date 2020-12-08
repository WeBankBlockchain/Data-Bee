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
package com.webank.blockchain.data.export.codegen.vo;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * Web3jTypeVO
 *
 * @Description: Web3jTypeVO
 * @author maojiayu
 * @data Oct 22, 2019 2:25:20 PM
 *
 */
@Data
@Accessors(chain = true)
public class Web3jTypeVO {

    private String solidityType;
    private String sqlType;
    private String javaType;
    private String typeMethod;

}
