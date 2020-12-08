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
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.code.template.face.ConfigGenerateParas;
import com.webank.blockchain.data.export.codegen.config.ButtonEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.config.ESBeanConfig;
import com.webank.blockchain.data.export.codegen.config.ServerConfig;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.config.ZookeeperConfig;
import com.webank.blockchain.data.export.codegen.constants.ConfigConstants;
import com.webank.blockchain.data.export.codegen.constants.ConfigFileConstants;
import com.webank.blockchain.data.export.codegen.constants.PackageConstants;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import com.webank.blockchain.data.export.codegen.enums.SubProjectEnum;
import com.webank.blockchain.data.export.codegen.vo.ContractInfo;
import com.webank.blockchain.data.export.codegen.vo.EventMetaInfo;
import com.webank.blockchain.data.export.codegen.vo.MethodMetaInfo;

/**
 * ApplicationPropParas to generate application.properties.
 *
 * @author maojiayu
 * @data Dec 28, 2018 2:47:01 PM
 *
 */
@Component
public class ApplicationPropParas implements ConfigGenerateParas {

    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;
    @Autowired
    private ButtonEnvironmentConfig buttonEnvironmentConfig;
    @Autowired
    private ServerConfig serverConfig;
    @Autowired
    private ZookeeperConfig zookeeperConfig;
    @Autowired
    private ESBeanConfig esConfig;

    @Override
    public Map<String, Object> getMap(ContractInfo info) {
        List<EventMetaInfo> eventList = info.getEventList();
        List<MethodMetaInfo> methodList = info.getMethodList();
        Map<String, Object> map = Maps.newLinkedHashMap();
        map.put("eventList", eventList);
        map.put("methodList", methodList);
        map.put("port", serverConfig.getPort());
        map.put("nodeStr", systemEnvironmentConfig.getNodeStr());
        map.put("groupId", StringUtils.split(systemEnvironmentConfig.getGroupId(), ',')[0]);
        map.put("group", systemEnvironmentConfig.getGroup());
        map.put("projectName", PackageConstants.PROJECT_PKG_NAME + "." + PackageConstants.SUB_PROJECT_PKG_CORE);
        map.put("multiLiving", systemEnvironmentConfig.getMultiLiving());
        map.put("contractPackName", systemEnvironmentConfig.getContractPackName());
        map.put("contractPath", ConfigConstants.CONTRACT_PATH);
        map.put("crawlBatchUnit", systemEnvironmentConfig.getCrawlBatchUnit());
        map.put("frequency", systemEnvironmentConfig.getFrequency());
        map.put("serverListStr", zookeeperConfig.getServerList());
        map.put("nameSpace", zookeeperConfig.getNamespace());
        map.put("startBlockHeight", systemEnvironmentConfig.getStartBlockHeight());
        map.put("startDate", systemEnvironmentConfig.getStartDate());
        map.put("encryptType", systemEnvironmentConfig.getEncryptType());
        map.put("esEnabled", esConfig.getEnabled());
        map.put("esClusterName", esConfig.getClusterName());
        map.put("esIp", esConfig.getIp());
        map.put("esPort", esConfig.getPort());

        map.put("swagger", buttonEnvironmentConfig.getSwagger());

        return map;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.APPLICATION_PROPERTIES_PATH;
    }

    @Override
    public String getGeneratedFilePath(ContractInfo info) {
        return SubProjectEnum.CORE.getPathName() + File.separator
                + ConfigFileConstants.GENERATED_APPLICATION_PROPERTIES_FILE_PATH;
    }
}
