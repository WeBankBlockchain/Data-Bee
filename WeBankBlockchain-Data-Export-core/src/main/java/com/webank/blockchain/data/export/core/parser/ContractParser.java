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
package com.webank.blockchain.data.export.core.parser;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition.NamedType;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.crypto.hash.Keccak256;
import org.fisco.bcos.sdk.model.TransactionReceipt.Logs;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.util.CollectionUtils;

import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.bo.contract.EventMetaInfo;
import com.webank.blockchain.data.export.common.bo.contract.FieldVO;
import com.webank.blockchain.data.export.common.bo.contract.MethodMetaInfo;
import com.webank.blockchain.data.export.common.bo.data.ContractInfoBO;
import com.webank.blockchain.data.export.common.constants.AbiTypeConstants;
import com.webank.blockchain.data.export.common.tools.ClazzScanUtils;
import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import com.webank.blockchain.data.export.common.tools.MethodUtils;
import com.webank.blockchain.data.export.core.config.SystemEnvironmentConfig;

import lombok.extern.slf4j.Slf4j;

/**
 * 
 * ContractParser using for getting contract java code file info, that will be used to parse transaction data.
 *
 * @Description: ContractParser
 * @author graysonzhang
 * @author maojiayu
 * @data 2018-12-17 15:06:51
 *
 */
@Configuration
@Slf4j
@DependsOn("cryptoKeyPair")
public class ContractParser {
    public static final String EVENT_RESPONSE = "EventResponse";

    /** @Fields monitorGeneratedConfig : monitor config params start with monitor in application.properties file */
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;
    @Autowired
    private Client client;

    /**
     * Parsing all contract java code files from contract path, and storage contract info into ContractMethodInfo
     * object, and return ContractMethodInfo object list.
     * 
     * @return List<ContractMethodInfo>
     */
    @Bean
    public List<ContractDetail> contractDetailList() throws Exception {
        List<ContractDetail> contractMethodInfos = Lists.newArrayList();
        Set<Class<?>> clazzs = ClazzScanUtils.scan(systemEnvironmentConfig.getContractPath(),
                systemEnvironmentConfig.getContractPackName());
        for (Class<?> clazz : clazzs) {
            ContractDetail detail = parse(clazz);
            if(detail == null) {
                continue;
            }
            detail.setEventMetaInfos(parseToEventInfoList(clazz));
            contractMethodInfos.add(detail);
        }
        return contractMethodInfos;
    }

    /**
     * Parsing single class object of contract java code file, and storage contract info into ContractMethodInfo object,
     * firstly, remove event function, query function and functions that param's null, compute methodId and save method
     * info into ContractMethodInfo object.
     * 
     * @param clazz: class object of contract java code file.
     * @return ContractMethodInfo
     */
    public ContractDetail parse(Class<?> clazz) throws Exception {
        List<ABIDefinition> abiDefinitions = MethodUtils.getContractAbiList(clazz);
        if (CollectionUtils.isEmpty(abiDefinitions)) {
            return null;
        }
        String className = clazz.getSimpleName();
        ContractDetail contractMethodInfo = new ContractDetail();
        ContractInfoBO contractInfoBO = new ContractInfoBO();
        contractInfoBO.setContractName(className);
        // get binary by crypto Type
        Method method = clazz.getDeclaredMethod("getBinary", CryptoSuite.class);
        String binary = (String) method.invoke(null, client.getCryptoSuite());
        contractInfoBO.setContractBinary(binary);
        contractInfoBO.setContractABI(MethodUtils.getClassField(clazz, "ABI"));
        contractInfoBO.setAbiHash(new Keccak256().hash(contractInfoBO.getContractABI()));
        contractMethodInfo.setContractInfoBO(contractInfoBO);
        List<MethodMetaInfo> methodIdList = Lists.newArrayListWithExpectedSize(abiDefinitions.size());
        contractMethodInfo.setMethodMetaInfos(methodIdList);

        for (ABIDefinition abiDefinition : abiDefinitions) {
            String abiType = abiDefinition.getType();
            // remove event function and query function
            if (abiType.equals(AbiTypeConstants.ABI_EVENT_TYPE) || abiDefinition.isConstant()) {
                continue;
            }
            // remove functions that input'params is null
            List<NamedType> inputs = abiDefinition.getInputs();
            if (inputs == null || inputs.isEmpty()) {
                continue;
            }
            String methodName = abiDefinition.getName();
            if (abiType.equals(AbiTypeConstants.ABI_CONSTRUCTOR_TYPE)) {
                methodName = "constructor";
            }
            // compute method id by method name and method input's params.
            String methodId = abiDefinition.getMethodId(client.getCryptoSuite());
            log.debug("methodId {} , methodName {}", methodId, methodName);
            MethodMetaInfo metaInfo = new MethodMetaInfo();
            metaInfo.setMethodId(methodId);
            metaInfo.setMethodName(methodName);
            metaInfo.setFieldsList(inputs);
            metaInfo.setOutputFieldsList(abiDefinition.getOutputs());
            methodIdList.add(metaInfo);
        }
        return contractMethodInfo;
    }

    public List<EventMetaInfo> parseToEventInfoList(Class<?> clazz) {
        Class<?>[] subClass = clazz.getClasses();
        List<EventMetaInfo> lists = Lists.newArrayList();
        for (Class<?> c : subClass) {
            // filter web3sdk 2.0 embedded contract subclass EventValuesWithLog.
            if (c.getSimpleName().equalsIgnoreCase("EventValuesWithLog")) {
                continue;
            }
            EventMetaInfo event = new EventMetaInfo();
            event.setEventName(StringUtils.substringBefore(c.getSimpleName(), EVENT_RESPONSE))
                    .setContractName(clazz.getSimpleName());

            Field[] fields = c.getFields();
            List<FieldVO> fieldList = Lists.newArrayList();
            for (Field f : fields) {
                // web3sdk 2.0 has a Log type, skip it temporary
                if (f.getType() == Logs.class) {
                    continue;
                }
                FieldVO vo = new FieldVO();
                String k = f.getName();
                String javaType = cleanType(f.getGenericType().getTypeName());
                // get the personal length
                if (StringUtils.isEmpty(k) || StringUtils.isEmpty(javaType)) {
                    continue;
                }
                vo.setJavaName(k).setJavaType(javaType).setJavaCapName(StringUtils.capitalize(k));
                log.debug(JacksonUtils.toJson(vo));
                fieldList.add(vo);
            }
            event.setList(fieldList);
            lists.add(event);
        }
        return lists;
    }

    /**
     * Translate all contract info of ContractMethodInfo's objects to methodIdMap and contractBinaryMap.
     * 
     * @param contractMethodInfos: contractMethodInfos contains methodIdMap and contractBinaryMap.
     * @return ContractMapsInfo
     */
    @Bean
    @DependsOn("contractDetailList")
    public ContractMapsInfo transContractMethodInfo2ContractMapsInfo() throws Exception {
        List<ContractDetail> contractMethodInfos = contractDetailList();
        ContractMapsInfo contractMapsInfo = new ContractMapsInfo();
        Map<String, MethodMetaInfo> methodIdMap = new HashMap<>();
        Map<String, ContractDetail> contractBinaryMap = new HashMap<>();
        for (ContractDetail contractMethodInfo : contractMethodInfos) {
            for (MethodMetaInfo methodMetaInfo : contractMethodInfo.getMethodMetaInfos()) {
                methodIdMap.put(methodMetaInfo.getMethodId(), methodMetaInfo);
                contractBinaryMap.put(contractMethodInfo.getContractInfoBO().getContractBinary(), contractMethodInfo);
            }
        }
        log.info("Init sync block: find {} contract constructors.", contractBinaryMap.size());
        contractMapsInfo.setContractBinaryMap(contractBinaryMap);
        contractMapsInfo.setMethodIdMap(methodIdMap);
        return contractMapsInfo;
    }

    public String cleanType(String genericType) {
        if ("byte[]".equals(genericType)) {
            return genericType;
        }
        if ("java.util.List<byte[]>".equals(genericType)) {
            return "List<byte[]>";
        }
        if (genericType.contains("<")) {
            return StringUtils.substringAfterLast(StringUtils.substringBefore(genericType, "<"), ".") + "<"
                    + StringUtils.substringAfterLast(StringUtils.substringAfter(genericType, "<"), ".");
        } else {
            return StringUtils.substringAfterLast(genericType, ".");
        }
    }
}
