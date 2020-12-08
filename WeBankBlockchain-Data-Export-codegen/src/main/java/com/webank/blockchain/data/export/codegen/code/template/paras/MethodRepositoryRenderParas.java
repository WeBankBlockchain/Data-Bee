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

import com.webank.blockchain.data.export.codegen.code.template.face.MethodGenerateParas;
import com.webank.blockchain.data.export.codegen.constants.PackageConstants;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.vo.MethodMetaInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.tools.PackagePath;

/**
 * MethodRepositoryRenderParas uses to installing params for generating method repositories.
 *
 * @Description: MethodRepositoryRenderParas
 * @author graysonzhang
 * @data 2018-12-4 21:43:56
 *
 */
@Component
public class MethodRepositoryRenderParas implements MethodGenerateParas {
    @Autowired
    protected SystemEnvironmentConfig systemEnvironmentConfig;

    @Override
    public Map<String, Object> getMap(MethodMetaInfo method) {
        Map<String, Object> map = Maps.newLinkedHashMap();
        String className = method.getContractName() + StringUtils.capitalize(method.getName());
        map.put("class_name", className);
        map.put("group", systemEnvironmentConfig.getGroup());
        map.put("projectName", PackageConstants.PROJECT_PKG_NAME + "." + PackageConstants.SUB_PROJECT_PKG_DB);
        return map;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.DB_MEHTOD_REPOSITORY_TEMPLATE_PATH;
    }

    @Override
    public String getGeneratedFilePath(MethodMetaInfo method) {
        String packagePath = PackagePath.getPackagePath(PackageConstants.DB__METHOD_REPOSITORY_PACKAGE_POSTFIX,
                systemEnvironmentConfig.getGroup(), PackageConstants.SUB_PROJECT_PKG_DB);
        String className = method.getContractName() + StringUtils.capitalize(method.getName());
        String javaFilePath = packagePath + "/" + className + "MethodRepository.java";
        return javaFilePath;
    }
}
