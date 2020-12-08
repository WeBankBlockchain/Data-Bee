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
package com.webank.blockchain.data.export.codegen.parser;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition.NamedType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.constants.ParserConstants;
import com.webank.blockchain.data.export.codegen.tools.ABIUtils;
import com.webank.blockchain.data.export.codegen.tools.PropertiesUtils;
import com.webank.blockchain.data.export.codegen.tools.SolJavaTypeMappingUtils;
import com.webank.blockchain.data.export.codegen.tools.SolSqlTypeMappingUtils;
import com.webank.blockchain.data.export.codegen.tools.SolTypeMethodMappingUtils;
import com.webank.blockchain.data.export.codegen.tools.StringStyleUtils;
import com.webank.blockchain.data.export.codegen.vo.FieldVO;
import com.webank.blockchain.data.export.codegen.vo.MethodMetaInfo;
import com.webank.blockchain.data.export.common.constants.AbiTypeConstants;

import cn.hutool.core.util.ArrayUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * MethodParser can parse contract files of java to standard method data structures.
 *
 * @Description: MethodParser
 * @author graysonzhang
 * @author maojiayu
 * @data 2018-12-4 23:04:50
 *
 */
@Slf4j
@Service
public class MethodParser implements ContractJavaParserInterface<MethodMetaInfo> {
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;

    public List<MethodMetaInfo> parseToInfoList(Class<?> clazz) {
        ABIDefinition[] abiDefinitions = ABIUtils.getContractAbiList(clazz);
        if (ArrayUtil.isEmpty(abiDefinitions)) {
            return null;
        }
        List<MethodMetaInfo> lists = Lists.newArrayList();
        for (ABIDefinition abiDefinition : abiDefinitions) {
            String abiType = abiDefinition.getType();
            if (abiType.equals(AbiTypeConstants.ABI_EVENT_TYPE) || abiDefinition.isConstant()) {
                continue;
            }
            List<NamedType> inputs = abiDefinition.getInputs();
            if (CollectionUtils.isEmpty(inputs) || StringUtils.isEmpty(inputs.get(0).getName())) {
                continue;
            }
            List<NamedType> outputs = abiDefinition.getOutputs();
            MethodMetaInfo method = new MethodMetaInfo();
            method.setType("method").setContractName(clazz.getSimpleName());
            log.debug("method name : {}", abiDefinition.getName());
            if (abiType.equals(AbiTypeConstants.ABI_CONSTRUCTOR_TYPE)) {
                method.setName("constructor");
            } else {
                method.setName(abiDefinition.getName());
            }
            String generatedFlag = PropertiesUtils.getGlobalProperty(ParserConstants.MONITOR, method.getContractName(),
                    method.getName(), "generated", "on");
            if (generatedFlag != null && generatedFlag.equalsIgnoreCase("off")) {
                continue;
            }
            int shardingNO = Integer.parseInt(PropertiesUtils.getGlobalProperty(ParserConstants.SYSTEM,
                    method.getContractName(), method.getName(), ParserConstants.SHARDINGNO, "1"));
            method.setShardingNO(shardingNO).setList(getFieldList(method, inputs))
                    .setOutputList(getOutputList(method, outputs));
            lists.add(method);
        }
        return lists;
    }

    public List<FieldVO> getOutputList(MethodMetaInfo method, List<NamedType> outputs) {
        if (CollectionUtils.isEmpty(outputs)) {
            return new ArrayList<FieldVO>();
        }
        List<FieldVO> list = Lists.newArrayListWithExpectedSize(outputs.size());
        for (int i = 0; i < outputs.size(); i++) {
            String javaName = "output" + (i + 1);
            String solType = outputs.get(i).getType();
            String length = PropertiesUtils.getGlobalProperty(ParserConstants.LENGTH, method.getContractName(),
                    method.getName(), javaName, "0");
            String sqlName =
                    systemEnvironmentConfig.getNamePrefix() + javaName + systemEnvironmentConfig.getNamePostfix();
            FieldVO vo = new FieldVO();
            vo.setJavaName(javaName).setJavaCapName(StringUtils.capitalize(javaName)).setSqlName(sqlName)
                    .setSqlType(SolSqlTypeMappingUtils.fromSolBasicTypeToSqlType(solType)).setSolidityType(solType)
                    .setJavaType(SolJavaTypeMappingUtils.fromSolBasicTypeToJavaType(solType))
                    .setTypeMethod(SolTypeMethodMappingUtils.fromSolBasicTypeToTypeMethod(solType))
                    .setLength(Integer.parseInt(length));
            list.add(vo);
        }
        return list;
    }

    public List<FieldVO> getFieldList(MethodMetaInfo method, List<NamedType> inputs) {
        ArrayList<FieldVO> fieldList = Lists.newArrayList();
        for (NamedType namedType : inputs) {
            FieldVO vo = new FieldVO();
            String solName = namedType.getName();
            // 增加is前缀变量的特殊处理
            if (StringUtils.startsWith(solName, "is") && solName.length() > 2
                    && Character.isUpperCase(solName.charAt(2))) {
                solName = StringUtils.uncapitalize(StringUtils.substring(solName, 2));
            }
            String solType = namedType.getType();
            String length = PropertiesUtils.getGlobalProperty(ParserConstants.LENGTH, method.getContractName(),
                    method.getName(), solName, "0");
            String sqlName = systemEnvironmentConfig.getNamePrefix() + StringStyleUtils.upper2underline(solName)
                    + systemEnvironmentConfig.getNamePostfix();
            vo.setSolidityName(solName).setSqlName(sqlName).setJavaName(solName)
                    .setSqlType(SolSqlTypeMappingUtils.fromSolBasicTypeToSqlType(solType)).setSolidityType(solType)
                    .setJavaType(SolJavaTypeMappingUtils.fromSolBasicTypeToJavaType(solType))
                    .setTypeMethod(SolTypeMethodMappingUtils.fromSolBasicTypeToTypeMethod(solType))
                    .setJavaCapName(StringUtils.capitalize(solName)).setLength(Integer.parseInt(length));
            log.debug("java name {}, java type {}, solidity type {}, type method {}", vo.getJavaName(),
                    vo.getJavaType(), vo.getSolidityType(), vo.getTypeMethod());
            fieldList.add(vo);
        }
        return fieldList;
    }

    
}
