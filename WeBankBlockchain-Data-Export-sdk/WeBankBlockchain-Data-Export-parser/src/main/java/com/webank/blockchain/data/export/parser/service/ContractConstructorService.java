/**
 * Copyright 2014-2019 the original author or authors.
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
package com.webank.blockchain.data.export.parser.service;

import java.util.Map;

import com.webank.blockchain.data.export.common.constants.ContractConstants;
import org.apache.commons.lang3.StringUtils;

import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.constants.BinConstant;

/**
 * ContractConstructorService for querying contract constructor name by input.
 *
 * @Description: ContractConstructorService
 * @author graysonzhang
 * @data 2018-12-19 18:16:59
 *
 */
public class ContractConstructorService {

    /**
     * Get entry that contains contract binary and contract constructor name. If prefix string of input matches some
     * binary of entry in binaryMap, return entry else return null.
     * 
     * @param input input of tx
     * @return key:contract binary, value:contract name
     */
    public static Map.Entry<String, ContractDetail> getConstructorNameByBinary(String input) {
        ContractMapsInfo contractMapsInfo = ContractConstants.getCurrentContractMaps();
        Map<String, ContractDetail> binaryMap = contractMapsInfo.getContractBinaryMap();
        for (Map.Entry<String, ContractDetail> entry : binaryMap.entrySet()) {
            String key = entry.getKey();
            if (input.length() > BinConstant.META_DATA_HASH_LENGTH
                    && key.length() > BinConstant.META_DATA_HASH_LENGTH) {
                key = key.substring(0, key.length() - 1 - BinConstant.META_DATA_HASH_LENGTH);
            } else {
                continue;
            }
            if (StringUtils.startsWithIgnoreCase(input.substring(2), key)) {
                return entry;
            }
        }
        return null;
    }

    /**
     * get constuctor name by transaction input code.
     * 
     * @param input input of tx
     * @return key:contract binary, value:contract name
     */
    public static Map.Entry<String, ContractDetail> getConstructorNameByCode(String input) {
        ContractMapsInfo contractMapsInfo = ContractConstants.getCurrentContractMaps();
        if (contractMapsInfo == null) {
            return null;
        }
        Map<String, ContractDetail> binaryMap = contractMapsInfo.getContractBinaryMap();
        for (Map.Entry<String, ContractDetail> entry : binaryMap.entrySet()) {
            String key = entry.getKey();
            if (input.length() > BinConstant.META_DATA_HASH_LENGTH
                    && key.length() > BinConstant.META_DATA_HASH_LENGTH) {
                input = input.substring(2, input.length() - 1 - BinConstant.META_DATA_HASH_LENGTH);
            } else {
                continue;
            }
            if (StringUtils.containsIgnoreCase(key, input)) {
                return entry;
            }
        }
        return null;
    }

}
