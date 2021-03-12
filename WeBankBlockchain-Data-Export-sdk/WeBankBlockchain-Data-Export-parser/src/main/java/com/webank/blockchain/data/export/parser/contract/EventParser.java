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
package com.webank.blockchain.data.export.parser.contract;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.util.StrUtil;
import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.common.bo.contract.EventMetaInfo;
import com.webank.blockchain.data.export.common.bo.contract.FieldVO;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import com.webank.blockchain.data.export.parser.enums.JavaTypeEnum;
import com.webank.blockchain.data.export.parser.tools.ABIUtils;
import com.webank.blockchain.data.export.parser.tools.SolJavaTypeMappingUtils;
import com.webank.blockchain.data.export.parser.vo.Web3jTypeVO;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition.NamedType;
import org.fisco.bcos.sdk.crypto.CryptoSuite;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * EventParser can parse contract files of java to standard event data structures.
 *
 * @author maojiayu
 * @date 2018-11-7 16:11:05
 * 
 */
@Slf4j
public class EventParser{

    private static Map<String, Web3jTypeVO> customMap = new HashMap<>();

    static {
        customMap.put("byte[]",
                new Web3jTypeVO().setJavaType("byte[]").setSolidityType("StaticArray<Bytes32>").
                        setSqlType("blob").setTypeMethod("String.valueOf"));
    }

    public static List<EventMetaInfo> parseToInfoList(String abiStr, String contractName) {
        Map<String, List<ABIDefinition>> eventsAbis =
                ABIUtils.getEventsAbiDefs(abiStr, new CryptoSuite(0));
        List<EventMetaInfo> list = new ArrayList<>();
        ExportConfig config = ExportConstant.getCurrentContext().getConfig();
        Map<String,List<String>> genOffMap = config.getGeneratedOff();
        List<String> contractGenOffs = null;
        if (CollectionUtil.isNotEmpty(genOffMap) && genOffMap.containsKey(contractName)) {
            contractGenOffs = genOffMap.get(contractName);
        }
        for (Map.Entry<String, List<ABIDefinition>> entry : eventsAbis.entrySet()) {
            String eventName = StringUtils.capitalize(entry.getKey());
            if (contractGenOffs != null && contractGenOffs.contains(eventName)){
                continue;
            }
            if (CollectionUtil.isEmpty(entry.getValue())) {
                log.error("Invalid parsed events, calss {} event {} abi ls empty.", contractName, eventName);
                continue;
            }
            if (entry.getValue().size() > 1) {
                log.warn("Overload parsed events, calss {} event {} abi ls empty.", contractName, eventName);
            }
            ABIDefinition abi = entry.getValue().get(0);
            EventMetaInfo eventMetaInfo = new EventMetaInfo();
            eventMetaInfo.setEventName(eventName).setContractName(contractName);
            List<NamedType> fields = abi.getInputs();
            List<FieldVO> fieldList = Lists.newArrayListWithExpectedSize(fields.size());
            for (NamedType namedType : fields) {
                if (namedType.isIndexed()) {
                    continue;
                }
                FieldVO vo = new FieldVO();
                String fieldName = namedType.getName();

                String javaType = SolJavaTypeMappingUtils.fromSolBasicTypeToJavaType(namedType.getType());
                if (StringUtils.isEmpty(fieldName) || StringUtils.isEmpty(javaType)) {
                    continue;
                }
                vo.setSolidityType(namedType.getType()).setJavaType(javaType).setJavaName(fieldName)
                        .setJavaCapName(StringUtils.capitalize(fieldName));
                setSqlAttribute(vo,eventName,contractName);
                log.debug(JacksonUtils.toJson(vo));
                fieldList.add(vo);
            }
            eventMetaInfo.setList(fieldList);
            list.add(eventMetaInfo);
        }
        return list;
    }

    public static FieldVO setSqlAttribute(FieldVO vo, String eventName, String contractName) {
        String javaType = vo.getJavaType();
        ExportConfig config = ExportConstant.getCurrentContext().getConfig();
        // get type from customMap
        if (customMap.containsKey(javaType)) {
            Web3jTypeVO typeVo = customMap.get(javaType);
            vo.setSqlType(typeVo.getSqlType()).setTypeMethod(typeVo.getTypeMethod());
        } else {
            JavaTypeEnum e = JavaTypeEnum.parse(javaType);
            vo.setSqlType(e.getSqlType()).setTypeMethod(e.getTypeMethod());
        }
        if (CollectionUtil.isNotEmpty(config.getParamSQLType())){
            Map<String, Map<String,Map<String,String>>> paramSQLType = config.getParamSQLType();
            if (paramSQLType.containsKey(contractName)){
                Map<String,Map<String,String>> methodTypeMap = paramSQLType.get(contractName);
                if (methodTypeMap.containsKey(eventName)){
                    Map<String,String> paramTypeMap = methodTypeMap.get(eventName);
                    if (paramTypeMap.containsKey(vo.getSolidityName())){
                        vo.setSqlType(paramTypeMap.get(vo.getSolidityName()));
                    }
                }
            }
        }

        // get the personal sql length of event field
        String sqlName = config.getNamePrefix() + StrUtil.toUnderlineCase(vo.getJavaName()) + config.getNamePostfix();
        vo.setSqlName(sqlName);
        return vo;
    }

}
