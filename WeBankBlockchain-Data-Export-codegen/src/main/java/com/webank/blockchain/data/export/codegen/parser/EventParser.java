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

import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition.NamedType;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.constants.ParserConstants;
import com.webank.blockchain.data.export.codegen.enums.JavaTypeEnum;
import com.webank.blockchain.data.export.codegen.tools.ABIUtils;
import com.webank.blockchain.data.export.codegen.tools.PropertiesUtils;
import com.webank.blockchain.data.export.codegen.tools.SolJavaTypeMappingUtils;
import com.webank.blockchain.data.export.codegen.tools.StringStyleUtils;
import com.webank.blockchain.data.export.codegen.vo.EventMetaInfo;
import com.webank.blockchain.data.export.codegen.vo.FieldVO;
import com.webank.blockchain.data.export.codegen.vo.Web3jTypeVO;
import com.webank.blockchain.data.export.common.tools.JacksonUtils;

import cn.hutool.core.text.StrSpliter;
import lombok.extern.slf4j.Slf4j;

/**
 * EventParser can parse contract files of java to standard event data structures.
 *
 * @author maojiayu
 * @date 2018-11-7 16:11:05
 * 
 */
@Slf4j
@Service
public class EventParser implements ContractJavaParserInterface<EventMetaInfo> {
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;
    @Autowired
    private Map<String, Web3jTypeVO> customMap;

    public List<EventMetaInfo> parseToInfoList(Class<?> clazz) {
        Map<String, List<ABIDefinition>> eventsAbis =
                ABIUtils.getEventsAbiDefs(ABIUtils.getContractAbi(clazz), new CryptoSuite(0));
        List<EventMetaInfo> lists = Lists.newArrayList();
        for (Map.Entry<String, List<ABIDefinition>> entry : eventsAbis.entrySet()) {
            String eventName = StringUtils.capitalize(entry.getKey());
            if (CollectionUtils.isEmpty(entry.getValue())) {
                log.error("Invalid parsed events, calss {} event {} abi ls empty.", clazz.getSimpleName(), eventName);
                continue;
            }
            if (entry.getValue().size() > 1) {
                log.warn("Overload parsed events, calss {} event {} abi ls empty.", clazz.getSimpleName(), eventName);
            }
            ABIDefinition abi = entry.getValue().get(0);
            EventMetaInfo eventMetaInfo = new EventMetaInfo();
            eventMetaInfo.setName(eventName).setType("event").setContractName(clazz.getSimpleName());
            if (skipGeneratedFlag(eventMetaInfo)) {
                continue;
            }
            eventMetaInfo = skipIgnoreParams(eventMetaInfo);
            eventMetaInfo = setShardingNo(eventMetaInfo);
            List<NamedType> fields = abi.getInputs();
            List<FieldVO> fieldList = Lists.newArrayListWithExpectedSize(fields.size());
            for (NamedType namedType : fields) {
                if (namedType.isIndexed()) {
                    continue;
                }
                FieldVO vo = new FieldVO();
                String fieldName = namedType.getName();
                if (eventMetaInfo.getIgnoreParams().contains(fieldName)) {
                    log.info("Contract:{}, event:{}, ignores param:{}", eventMetaInfo.getContractName(),
                            eventMetaInfo.getName(), fieldName);
                    continue;
                }
                String javaType = SolJavaTypeMappingUtils.fromSolBasicTypeToJavaType(namedType.getType());
                if (StringUtils.isEmpty(fieldName) || StringUtils.isEmpty(javaType)) {
                    continue;
                }
                vo.setSolidityType(namedType.getType()).setJavaType(javaType).setJavaName(fieldName)
                        .setJavaCapName(StringUtils.capitalize(fieldName));
                vo = setSqlAttribute(eventMetaInfo, vo);
                log.debug(JacksonUtils.toJson(vo));
                fieldList.add(vo);
            }
            eventMetaInfo.setList(fieldList);
            lists.add(eventMetaInfo);
        }
        return lists;
    }

    public FieldVO setSqlAttribute(EventMetaInfo eventMetaInfo, FieldVO vo) {
        String javaType = vo.getJavaType();
        // get type from customMap
        if (customMap.containsKey(javaType)) {
            Web3jTypeVO typeVo = customMap.get(javaType);
            vo.setSqlType(typeVo.getSqlType()).setTypeMethod(typeVo.getTypeMethod())
                    .setEntityType(typeVo.getJavaType());
        } else {
            JavaTypeEnum e = JavaTypeEnum.parse(javaType);
            vo.setSqlType(e.getSqlType()).setEntityType(e.getEntityType()).setTypeMethod(e.getTypeMethod());
        }
        // get the personal sql length of event field
        String length = PropertiesUtils.getGlobalProperty(ParserConstants.LENGTH, eventMetaInfo.getContractName(),
                eventMetaInfo.getName(), vo.getJavaName(), "0");
        String sqlName = systemEnvironmentConfig.getNamePrefix() + StringStyleUtils.upper2underline(vo.getJavaName())
                + systemEnvironmentConfig.getNamePostfix();
        vo.setSqlName(sqlName).setLength(Integer.parseInt(length));
        return vo;
    }

    public boolean skipGeneratedFlag(EventMetaInfo eventMetaInfo) {
        String generatedFlag = PropertiesUtils.getGlobalProperty(ParserConstants.MONITOR,
                eventMetaInfo.getContractName(), eventMetaInfo.getName(), "generated", "on");
        if (generatedFlag != null && generatedFlag.equalsIgnoreCase("off")) {
            return true;
        } else {
            return false;
        }
    }

    public EventMetaInfo skipIgnoreParams(EventMetaInfo eventMetaInfo) {
        String ignoreStr = PropertiesUtils.getPropertyWithoutDefault(ParserConstants.MONITOR,
                eventMetaInfo.getContractName(), eventMetaInfo.getName(), ParserConstants.IGNORE_PARAM);
        List<String> ignoreParam = StrSpliter.split(ignoreStr, ',', 0, true, true);
        eventMetaInfo.setIgnoreParams(ignoreParam);
        return eventMetaInfo;
    }

    public EventMetaInfo setShardingNo(EventMetaInfo eventMetaInfo) {
        int shardingNO = Integer.parseInt(PropertiesUtils.getGlobalProperty(ParserConstants.SYSTEM,
                eventMetaInfo.getContractName(), eventMetaInfo.getName(), ParserConstants.SHARDINGNO, "1"));
        eventMetaInfo.setShardingNO(shardingNO);
        return eventMetaInfo;
    }
}
