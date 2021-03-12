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
package com.webank.blockchain.data.export.db.repository;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.db.DaoTemplate;
import cn.hutool.db.Entity;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.db.entity.BlockRawData;
import com.webank.blockchain.data.export.db.entity.BlockTaskPool;
import com.webank.blockchain.data.export.db.entity.ContractInfo;
import com.webank.blockchain.data.export.db.tools.BeanUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.sql.SQLException;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Slf4j
@AllArgsConstructor
public class ContractInfoRepository {

    private DaoTemplate contractDao;

    public void save(ContractInfo contractInfo) {
        try {
            contractDao.add(Entity.parse(contractInfo,true,true));
        } catch (SQLException e) {
            log.error("ContractInfoRepository save failed ", e);
        }
    }

    public ContractInfo findByAbiHash(String abiHash) {
        Entity entity = null;
        try {
            entity = contractDao.get("abi_hash",abiHash);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findTopByOrderByBlockHeightDesc failed ", e);
        }
        if (entity == null){
            return null;
        }
        return BeanUtils.toBean(entity, ContractInfo.class);

    }
}
