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

import com.webank.blockchain.data.export.codegen.code.template.face.EventGenerateParas;
import com.webank.blockchain.data.export.codegen.constants.TemplateConstants;
import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.vo.FieldVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.codegen.enums.SubProjectEnum;
import com.webank.blockchain.data.export.codegen.tools.SqlNameUtils;
import com.webank.blockchain.data.export.codegen.tools.StringStyleUtils;
import com.webank.blockchain.data.export.codegen.vo.EventMetaInfo;

/**
 * EventSqlFileRenderParas to generate event sql file.
 *
 * @Description: the generated sql file isn't used directly, Actually we use hibernate to operate db instead. This
 *               record of sql files are still important.
 * @author maojiayu
 * @data Dec 28, 2018 3:06:14 PM
 *
 */
@Component
public class EventSqlFileRenderParas implements EventGenerateParas {
    @Autowired
    protected SystemEnvironmentConfig systemEnvironmentConfig;
    @Autowired
    private SqlNameUtils sqlNameUtils;

    /*
     * input: 0-List<FieldVO> 字段属性; 1-String SQL表名;
     */
    @Override
    public Map<String, Object> getMap(EventMetaInfo event) {
        List<FieldVO> list = event.getList();
        Map<String, Object> map = Maps.newLinkedHashMap();
        map.put("list", list);
        String tableName = sqlNameUtils.getSqlName(event.getContractName(), event.getName()) + "_event";
        map.put("table_name", tableName);
        return map;
    }

    @Override
    public String getTemplatePath() {
        return TemplateConstants.SQL_EVENT_TEMPLATE_PATH;
    }

    @Override
    public String getGeneratedFilePath(EventMetaInfo event) {
        String javaFilePath = SubProjectEnum.CORE.getPathName() + File.separator + "src/main/scripts/event/"
                + StringStyleUtils.upper2underline(event.getName()) + ".sql";
        return javaFilePath;
    }

}
