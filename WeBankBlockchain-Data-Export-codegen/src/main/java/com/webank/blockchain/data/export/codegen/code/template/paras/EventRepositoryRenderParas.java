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

import java.util.Map;

import com.webank.blockchain.data.export.codegen.code.template.face.EventGenerateParas;
import com.webank.blockchain.data.export.codegen.constants.PackageConstants;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.tools.PackagePath;
import com.webank.blockchain.data.export.codegen.vo.EventMetaInfo;

/**
 * EventRepositoryRenderParas to generate repository of events.
 *
 * @author maojiayu
 * @data Dec 28, 2018 3:05:42 PM
 *
 */
@Component
public class EventRepositoryRenderParas implements EventGenerateParas {
    @Autowired
    protected SystemEnvironmentConfig systemEnvironmentConfig;

    /*
     * input: 0-String 类名;
     */
    @Override
    public Map<String, Object> getMap(EventMetaInfo event) {
        Map<String, Object> map = Maps.newLinkedHashMap();
        String className = event.getContractName() + event.getName();
        map.put("class_name", className);
        map.put("group", systemEnvironmentConfig.getGroup());
        map.put("projectName", PackageConstants.PROJECT_PKG_NAME + "." + PackageConstants.SUB_PROJECT_PKG_DB);
        return map;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.DB_EVENT_REPOSITORY_TEMPLATE_PATH;
    }

    @Override
    public String getGeneratedFilePath(EventMetaInfo event) {
        String packagePath = PackagePath.getPackagePath(PackageConstants.DB_EVENT_REPOSITORY_PACKAGE_POSTFIX,
                systemEnvironmentConfig.getGroup(), PackageConstants.SUB_PROJECT_PKG_DB);
        String className = event.getContractName() + event.getName();
        String javaFilePath = packagePath + "/" + className + "EventRepository.java";
        return javaFilePath;
    }

}
