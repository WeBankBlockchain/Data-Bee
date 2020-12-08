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

import java.util.List;
import java.util.Map;

import com.webank.blockchain.data.export.codegen.code.template.face.EventGenerateParas;
import com.webank.blockchain.data.export.codegen.constants.PackageConstants;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.vo.FieldVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.tools.PackagePath;
import com.webank.blockchain.data.export.codegen.vo.EventMetaInfo;

/**
 * EventCrawlImplParas to generate EventCrawler.
 *
 * @author maojiayu
 * @data Dec 28, 2018 2:59:25 PM
 *
 */
@Component
public class EventCrawlImplParas implements EventGenerateParas {

    @Autowired
    protected SystemEnvironmentConfig systemEnvironmentConfig;

    @Override
    public Map<String, Object> getMap(EventMetaInfo event) {
        List<FieldVO> list = event.getList();
        Map<String, Object> map = Maps.newLinkedHashMap();
        map.put("list", list);
        map.put("contractName", event.getContractName());
        map.put("lowContractName", StringUtils.uncapitalize(event.getContractName()));
        map.put("group", systemEnvironmentConfig.getGroup());
        map.put("projectName", PackageConstants.PROJECT_PKG_NAME + "." + PackageConstants.SUB_PROJECT_PKG_PARSER);
        map.put("contractPackName", systemEnvironmentConfig.getContractPackName());
        map.put("eventName", event.getName());
        String className = event.getContractName() + event.getName() + "BO";
        map.put("class_name", className);
        return map;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.CRAWLER_EVENT_IMPL_TEMPLATE_PATH;
    }

    @Override
    public String getGeneratedFilePath(EventMetaInfo event) {
        String packagePath = PackagePath.getPackagePath(PackageConstants.CRAWLER_EVENT_IMPL_PACKAGE_POSTFIX,
                systemEnvironmentConfig.getGroup(), PackageConstants.SUB_PROJECT_PKG_PARSER);
        String javaFilePath = packagePath + "/" + event.getContractName() + StringUtils.capitalize(event.getName())
                + "CrawlerImpl.java";
        return javaFilePath;
    }

}
