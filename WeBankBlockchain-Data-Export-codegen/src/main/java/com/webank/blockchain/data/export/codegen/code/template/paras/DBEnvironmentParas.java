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
package com.webank.blockchain.data.export.codegen.code.template.paras;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.webank.blockchain.data.export.codegen.constants.ConfigFileConstants;
import com.webank.blockchain.data.export.codegen.constants.ParserConstants;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.code.template.face.ConfigGenerateParas;
import com.webank.blockchain.data.export.codegen.enums.SubProjectEnum;
import com.webank.blockchain.data.export.codegen.enums.SysTableEnum;
import com.webank.blockchain.data.export.codegen.tools.PropertiesUtils;
import com.webank.blockchain.data.export.codegen.tools.SqlNameUtils;
import com.webank.blockchain.data.export.codegen.vo.ContractInfo;
import com.webank.blockchain.data.export.codegen.vo.ContractStructureMetaInfo;
import com.webank.blockchain.data.export.codegen.vo.EventMetaInfo;
import com.webank.blockchain.data.export.codegen.vo.MethodMetaInfo;

import lombok.extern.slf4j.Slf4j;

/**
 * DBYmlParas to generate db.yml
 *
 * @author maojiayu
 * @data Dec 28, 2018 2:47:37 PM
 *
 */
@Component
@Slf4j
public class DBEnvironmentParas implements ConfigGenerateParas {

    @Autowired
    protected SystemEnvironmentConfig systemEnvironmentConfig;
    @Autowired
    private SqlNameUtils sqlNameUtils;

    @Override
    public Map<String, Object> getMap(ContractInfo contractsInfo) {
        Map<String, Object> map = Maps.newLinkedHashMap();
        map.put("dbUrl", systemEnvironmentConfig.getDbUrl());
        log.debug("dbUrl: {}", systemEnvironmentConfig.getDbUrl());
        map.put("dbUser", systemEnvironmentConfig.getDbUser());
        log.debug("dbUser: {}", systemEnvironmentConfig.getDbUser());
        map.put("dbPassword", systemEnvironmentConfig.getDbPassword());
        log.debug("dbPassword: {}", systemEnvironmentConfig.getDbPassword());

        List<EventMetaInfo> eventList = contractsInfo.getEventList();
        List<MethodMetaInfo> methodList = contractsInfo.getMethodList();
        List<ContractStructureMetaInfo> list = getContractStructureMetaInfoList(
                eventList.stream().map(e -> (ContractStructureMetaInfo) e).collect(Collectors.toList()));
        for (SysTableEnum e : SysTableEnum.values()) {
            int length = Integer.parseInt(PropertiesUtils.getGlobalProperty(ParserConstants.SYSTEM, "sys", e.getName(),
                    ParserConstants.SHARDINGNO, "0"));
            if (length > 0) {
                ContractStructureMetaInfo c =
                        new ContractStructureMetaInfo().setShardingNO(length).setName(e.getTableName());
                list.add(c);
            }
        }
        list.addAll(getContractStructureMetaInfoList(
                methodList.stream().map(e -> (ContractStructureMetaInfo) e).collect(Collectors.toList())));
        map.put("list", list);
        return map;
    }

    private List<ContractStructureMetaInfo> getContractStructureMetaInfoList(
            List<ContractStructureMetaInfo> ContractStructureMetaInfoList) {
        List<ContractStructureMetaInfo> list = new ArrayList<>();
        for (ContractStructureMetaInfo info : ContractStructureMetaInfoList) {
            if (info.getShardingNO() > 1) {
                String tableName = sqlNameUtils.getSqlName(info.getContractName(), info.getName());
                info.setName(tableName);
                list.add(info);
            }
        }
        return list;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.DB_PROPERTIES_PATH;
    }

    @Override
    public String getGeneratedFilePath(ContractInfo contractsInfo) {
        return SubProjectEnum.CORE.getPathName() + File.separator + ConfigFileConstants.GENERATED_DB_ENV_FILE_PATH;
    }
}
