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
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinitionFactory;
import org.fisco.bcos.sdk.abi.wrapper.ContractABIDefinition;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.utils.ObjectMapperFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webank.blockchain.data.export.codegen.constants.ParserConstants;

import lombok.extern.slf4j.Slf4j;

/**
 * ABIUtils
 *
 * @Description: ABIUtils
 * @author maojiayu
 * @data Nov 19, 2020 5:53:37 PM
 *
 */
@Slf4j
public class ABIUtils {

    public static Map<String, List<ABIDefinition>> getEventsAbiDefs(String abi, CryptoSuite cryptoSuite) {
        ABIDefinitionFactory abiDefinitionFactory = new ABIDefinitionFactory(cryptoSuite);
        ContractABIDefinition contractABIDefinition = abiDefinitionFactory.loadABI(abi);
        Map<String, List<ABIDefinition>> events = contractABIDefinition.getEvents();
        return events;
    }

    /**
     * Get contract abi list by contract class.
     * 
     * @param clazz
     * @return
     * @return AbiDefinition[]
     */
    public static ABIDefinition[] getContractAbiList(Class<?> clazz) {
        String abi = getContractAbi(clazz);

        ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
        ABIDefinition[] abiDefinition = null;

        try {
            abiDefinition = objectMapper.readValue(abi, ABIDefinition[].class);
        } catch (IOException e) {
            log.error("IOException: {}", e.getMessage());
        }
        return abiDefinition;
    }

    public static String getContractAbi(Class<?> clazz) {
        try {
            Field field = clazz.getField(ParserConstants.ABI);
            if (!field.isAccessible()) {
                field.setAccessible(true);
            }
            return (String) field.get(ParserConstants.ABI);
        } catch (NoSuchFieldException | SecurityException e) {
            log.error("Exception: {}", e.getMessage());
        } catch (IllegalArgumentException | IllegalAccessException e) {
            log.error("Illegal Exception: {}", e.getMessage());
        }
        return "";
    }
    
}
