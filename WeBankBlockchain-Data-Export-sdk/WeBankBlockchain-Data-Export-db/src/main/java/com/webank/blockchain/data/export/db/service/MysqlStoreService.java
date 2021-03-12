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
import com.webank.blockchain.data.export.db.dao.ContractInfoDAO;
import com.webank.blockchain.data.export.db.dao.SaveInterface;
import lombok.Data;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Data
public class MysqlStoreService implements DataStoreService{

    private List<SaveInterface<BlockInfoBO>> saveInterfaceList;

    private ContractInfoDAO contractInfoDAO;

    @Override
    public void storeBlockInfoBO(BlockInfoBO blockInfo) {
        saveInterfaceList.forEach(saveInterface -> {
            saveInterface.save(blockInfo);
        });
    }

    @Override
    public void storeContractInfo(ContractInfoBO contractInfoBO) {
        contractInfoDAO.save(contractInfoBO);
    }
}
