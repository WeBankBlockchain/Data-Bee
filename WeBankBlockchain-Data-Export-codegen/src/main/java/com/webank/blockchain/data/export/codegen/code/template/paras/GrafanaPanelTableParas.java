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

import com.webank.blockchain.data.export.codegen.code.template.face.AtomicParas;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import com.webank.blockchain.data.export.codegen.vo.FieldVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.tools.SqlNameUtils;
import com.webank.blockchain.data.export.codegen.vo.ContractStructureMetaInfo;

/**
 * GrafanaPanelParas
 *
 * @Description: GrafanaPanelParas
 * @author maojiayu
 * @data Mar 27, 2019 4:48:14 PM
 *
 */
@Component
public class GrafanaPanelTableParas implements AtomicParas<ContractStructureMetaInfo> {
    @Autowired
    private SqlNameUtils sqlNameUtils;

    @Override
    public Map<String, Object> getMap(ContractStructureMetaInfo info) {
        List<FieldVO> list = info.getList();
        Map<String, Object> map = Maps.newLinkedHashMap();
        map.put("list", list);
        String className = info.getContractName() + StringUtils.capitalize(info.getName());
        String tableName = sqlNameUtils.getSqlName(info.getContractName(), info.getName()+ "_" + info.getType());
        map.put("table_name", tableName);
        map.put("title", className);
        return map;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.GRAFANA_PANEL_TABLE_PATH;
    }

}
