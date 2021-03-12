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
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition.NamedType;

import java.util.List;

/**
 * MethodMetaInfo
 *
 * @Description: MethodMetaInfo storages method config data for parsing method data.
 * @author graysonzhang
 * @data 2018-12-17 14:20:00
 *
 */
@Data
@Accessors(chain = true)
public class MethodMetaInfo {

    /** @Fields methodId : method id */
    private String methodId;

    /** @Fields methodName : method name */
    private String methodName;

    private String type;

    /** @Fields contractName : contract name */
    private String contractName;

    /** @Fields fieldsList : method input param list */
    private List<FieldVO> fieldsList;
    
    private List<FieldVO> outputList;

}
