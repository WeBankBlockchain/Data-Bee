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

import com.webank.blockchain.data.export.db.dao.BlockCommonDAO;
import com.webank.blockchain.data.export.db.dao.BlockDetailInfoDAO;
import com.webank.blockchain.data.export.db.dao.BlockRawDataDAO;
import com.webank.blockchain.data.export.db.dao.BlockTxDetailInfoDAO;
import com.webank.blockchain.data.export.db.dao.ContractInfoDAO;
import com.webank.blockchain.data.export.db.dao.DeployedAccountInfoDAO;
import com.webank.blockchain.data.export.db.dao.TxRawDataDAO;
import com.webank.blockchain.data.export.db.dao.TxReceiptRawDataDAO;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.CommonBO;
import com.webank.blockchain.data.export.common.bo.data.ContractInfoBO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Component
public class MysqlStoreService implements DataStoreService{

    @Autowired
    private BlockDetailInfoDAO blockDetailInfoDao;
    @Autowired
    private BlockTxDetailInfoDAO blockTxDetailInfoDao;
    @Autowired
    private BlockCommonDAO blockEventDao;
    @Autowired
    private BlockRawDataDAO blockRawDataDao;
    @Autowired
    private TxRawDataDAO txRawDataDao;
    @Autowired
    private TxReceiptRawDataDAO txReceiptRawDataDao;
    @Autowired
    private DeployedAccountInfoDAO deployedAccountInfoDao;
    @Autowired
    private ContractInfoDAO contractInfoDAO;

    @Override
    public void storeBlockInfoBO(BlockInfoBO blockInfo) {
        blockDetailInfoDao.save(blockInfo.getBlockDetailInfo());
        blockRawDataDao.save(blockInfo.getBlockRawDataBO());
        txRawDataDao.save(blockInfo.getTxRawDataBOList());
        deployedAccountInfoDao.save(blockInfo.getDeployedAccountInfoBOS());
        txReceiptRawDataDao.save(blockInfo.getTxReceiptRawDataBOList());
        blockTxDetailInfoDao.save(blockInfo.getBlockTxDetailInfoList());
        blockEventDao.save(blockInfo.getEventInfoList().stream().map(e -> (CommonBO) e).collect(Collectors.toList()),
                "event");
        blockEventDao.save(blockInfo.getMethodInfoList().stream().map(e -> (CommonBO) e).collect(Collectors.toList()),
                "method");
    }

    @Override
    public void storeContractInfo(ContractInfoBO contractInfoBO) {
        contractInfoDAO.save(contractInfoBO);
    }
}
