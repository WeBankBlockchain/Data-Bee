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
package com.webank.blockchain.data.export.db.dao;

import cn.hutool.core.bean.BeanUtil;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.BlockTxDetailInfoBO;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.db.entity.BlockTxDetailInfo;
import com.webank.blockchain.data.export.db.repository.BlockTxDetailInfoRepository;
import lombok.AllArgsConstructor;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.sql.Date;
import java.util.List;

/**
 * BlockTxDetailInfoDAO
 *
 * @Description: Block transaction detail data access object
 * @author graysonzhang
 * @data 2018-12-20 15:01:27
 *
 */
@AllArgsConstructor
public class BlockTxDetailInfoDAO implements SaveInterface<BlockInfoBO>{

    /** @Fields blockTxDetailInfoRepository : block transaction detail info repository */
    private BlockTxDetailInfoRepository blockTxDetailInfoRepository;

    /**
     * Get block transaction detail info from transaction receipt object and insert BlockTxDetailInfo into db.
     * 
     * @param receipt : TransactionReceipt
     * @param blockTimeStamp
     * @param contractName: contract name
     * @param methodName: method name
     * @return void
     * @throws IOException
     */
    public void save(TransactionReceipt receipt, BigInteger blockTimeStamp, String contractName, String methodName)
            throws IOException {
        BlockTxDetailInfo blockTxDetailInfo = new BlockTxDetailInfo();
        blockTxDetailInfo.setBlockHash(receipt.getBlockHash());
        blockTxDetailInfo.setBlockHeight(Numeric.toBigInt(receipt.getBlockNumber()).longValue());
        blockTxDetailInfo.setContractName(contractName);
        blockTxDetailInfo.setMethodName(methodName.substring(contractName.length()));
        JsonTransactionResponse transaction = ExportConstant.getCurrentContext().getClient().
                getTransactionByHash(receipt.getTransactionHash()).getTransaction().get();
        blockTxDetailInfo.setTxFrom(transaction.getFrom());
        blockTxDetailInfo.setTxTo(transaction.getTo());
        blockTxDetailInfo.setTxHash(receipt.getTransactionHash());
        blockTxDetailInfo.setBlockTimeStamp(new Date(blockTimeStamp.longValue()));
        blockTxDetailInfoRepository.save(blockTxDetailInfo);
    }

    public void save(BlockTxDetailInfoBO bo) {
        BlockTxDetailInfo blockTxDetailInfo = new BlockTxDetailInfo();
        BeanUtil.copyProperties(bo, blockTxDetailInfo, true);
        blockTxDetailInfoRepository.save(blockTxDetailInfo);
    }

    public void save(List<BlockTxDetailInfoBO> list) {
        list.forEach(this::save);
    }

    @Override
    public void save(BlockInfoBO blockInfoBO) {
        save(blockInfoBO.getBlockTxDetailInfoList());
    }
}
