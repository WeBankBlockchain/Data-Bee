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

import com.webank.blockchain.data.export.codegen.constants.ConfigFileConstants;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.code.template.face.GrafanaParas;
import com.webank.blockchain.data.export.codegen.enums.SubProjectEnum;

/**
 * GrafanaDashboardParas
 *
 * @Description: GrafanaDashboardParas
 * @author maojiayu
 * @data Mar 28, 2019 11:12:50 AM
 *
 */
@Component
public class GrafanaDashboardParas implements GrafanaParas<List<String>> {

    @Override
    public Map<String, Object> getMap(List<String> infoList) {
        Map<String, Object> map = Maps.newLinkedHashMap();
        map.put("panels", infoList);
        return map;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.GRAFANA_DASHBOARD_PATH;
    }

    @Override
    public String getGeneratedFilePath() {
        return SubProjectEnum.CORE.getPathName() + File.separator
                + ConfigFileConstants.GENERATED_GRAFANA_DEFAULT_DASHBOARD_PATH;
    }

}
