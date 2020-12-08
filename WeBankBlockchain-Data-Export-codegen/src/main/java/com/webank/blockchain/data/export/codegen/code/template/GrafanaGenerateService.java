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
package com.webank.blockchain.data.export.codegen.code.template;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.webank.blockchain.data.export.codegen.code.service.ContractInfoService;
import com.webank.blockchain.data.export.codegen.code.template.paras.GrafanaDashboardParas;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.code.template.paras.GrafanaPanelTableParas;
import org.apache.commons.io.FileUtils;
import org.beetl.core.GroupTemplate;
import org.beetl.core.Template;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.codegen.vo.ContractInfo;
import com.webank.blockchain.data.export.codegen.vo.ContractStructureMetaInfo;

import lombok.extern.slf4j.Slf4j;

/**
 * GrafanaGenerateService
 *
 * @Description: GrafanaGenerateService
 * @author maojiayu
 * @data Mar 27, 2019 5:25:27 PM
 *
 */
@Service
@Slf4j
public class GrafanaGenerateService {
    /** @Fields gt : group template */
    @Autowired
    protected GroupTemplate gt;
    @Autowired
    protected SystemEnvironmentConfig systemEnvironmentConfig;
    @Autowired
    private ContractInfoService contractInfoService;
    @Autowired
    private GrafanaPanelTableParas panelPara;
    @Autowired
    private GrafanaDashboardParas grafanaDashboardParas;

    public void genereate() throws ClassNotFoundException, IOException {
        List<String> panels = Lists.newArrayList();
        ContractInfo info = contractInfoService.parseFromContract();
        List<ContractStructureMetaInfo> tablesList = Lists.newArrayList();
        tablesList.addAll(info.getEventList());
        tablesList.addAll(info.getMethodList());
        Template template = gt.getTemplate(panelPara.getTemplatePath());
        int index = 1;
        for (ContractStructureMetaInfo e : tablesList) {
            Map<String, Object> map = panelPara.getMap(e);
            map.put("gridXPos", getX(index));
            map.put("gridYPos", getY(index));
            map.put("id", getId(index));
            template.binding(map);
            String panelStr = template.render();
            panels.add(panelStr);
            index++;
        }
        Map<String, Object> map = grafanaDashboardParas.getMap(panels);
        Template dashboardTemplate = gt.getTemplate(grafanaDashboardParas.getTemplatePath());
        dashboardTemplate.binding(map);
        String dashboardStr = dashboardTemplate.render();
        write(dashboardStr);

    }

    public void write(String dashboardStr) {
        try {
            log.info("Begin to create grafana file: {}", grafanaDashboardParas.getGeneratedFilePath());
            FileUtils.write(new File(systemEnvironmentConfig.getBaseProjectPath() + File.separator
                    + grafanaDashboardParas.getGeneratedFilePath()), dashboardStr, "utf-8", false);
            log.info("Write succeed: {}", grafanaDashboardParas.getGeneratedFilePath());
        } catch (IOException e1) {
            log.error("Grafana Dashboard json file create. Error occourred: {}", e1.getMessage());
        }
    }

    public int getX(int index) {
        /*
         * if (index % 2 == 0) { return 12; } else { return 0; }
         */
        return 0;

    }

    public int getY(int index) {
        // index = (index + 1) / 2;
        // return 32 + index * 8;
        return 24 + index * 8;
    }

    public int getId(int index) {
        return index + 30;
    }

}
