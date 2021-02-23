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

import java.util.Map;

/**
 * ContractMapsInfo
 *
 * @Description: ContractMapsInfo storages contract info, that will used to parse method data.
 * @author graysonzhang
 * @data 2018-12-17 14:55:20
 *
 */
@Data
@Accessors(chain = true)
public class ContractMapsInfo {

    /** @Fields methodIdMap : use to storage methodId map , key:methodId, value:(contractName, methodName) */
    private Map<String, MethodMetaInfo> methodIdMap;
    
    /** @Fields contractBinaryMap : use to storage contract binary map, key:contract binary, value:contract name */
    private Map<String, ContractDetail> contractBinaryMap;

}
