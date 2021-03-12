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
package com.webank.blockchain.data.export.db.service;

import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.ContractInfoBO;
import com.webank.blockchain.data.export.db.dao.ESHandleDao;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Slf4j
@Data
public class ESStoreService implements DataStoreService{

    @Override
    public void storeBlockInfoBO(BlockInfoBO blockInfo) {
        try {
            ESHandleDao.saveBlockInfo(blockInfo);
        } catch (Exception e) {
            log.error("ES storeBlockInfoBO failed, reason : " , e);
        }
    }

    @Override
    public void storeContractInfo(ContractInfoBO contractInfoBO) {
        try {
            ESHandleDao.saveContractInfo(contractInfoBO);
        } catch (Exception e) {
            log.error("ES storeContractInfo failed, reason : " , e);
        }
    }
}
