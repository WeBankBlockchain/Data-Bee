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
package com.webank.blockchain.data.export.parser.handler;

import com.webank.blockchain.data.export.common.bo.data.BlockDetailInfoBO;
import com.webank.blockchain.data.export.common.bo.data.BlockDetailInfoBO.Status;
import com.webank.blockchain.data.export.common.bo.data.BlockRawDataBO;
import com.webank.blockchain.data.export.common.tools.DateUtils;
import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.stereotype.Service;

/**
 * BlockCrawlerHandler is responsible for crawling block info.
 *
 * @Description: BlockCrawlerHandler
 * @author graysonzhang
 * @author maojiayu
 * @data 2018-12-20 14:32:58
 *
 */
@Service
public class BlockCrawlerHandler {

    /**
     * Get block detail info form block object, and insert into db. Block detail info contains block height,
     * transaction's count in current block, block hash and block timestamp.
     * 
     * @param block
     * @param blockHeight
     * @return boolean
     */
    public BlockDetailInfoBO handleBlockDetail(Block block) {
        BlockDetailInfoBO blockDetailInfo = new BlockDetailInfoBO();
        blockDetailInfo.setBlockHeight(block.getNumber().longValue());
        blockDetailInfo.setTxCount(block.getTransactions().size());
        blockDetailInfo.setBlockHash(block.getHash());
        blockDetailInfo.setBlockTimeStamp(DateUtils.hexStrToDate(block.getTimestamp()));
        blockDetailInfo.setStatus((short) Status.COMPLETED.ordinal());
        return blockDetailInfo;
    }

    public BlockRawDataBO handleBlockRawData(Block block) {
        BlockRawDataBO blockRawDataBO = new BlockRawDataBO();
        blockRawDataBO.setBlockHeight(block.getNumber().longValue());
        blockRawDataBO.setBlockHash(block.getHash());
        blockRawDataBO.setBlockTimeStamp(DateUtils.hexStrToDate(block.getTimestamp()));
        blockRawDataBO.setDbHash(block.getDbHash());
        blockRawDataBO.setExtraData(JacksonUtils.toJson(block.getExtraData()));
        blockRawDataBO.setGasLimit(block.getGasLimit());
        blockRawDataBO.setGasUsed(block.getGasUsed());
        blockRawDataBO.setLogsBloom(block.getLogsBloom());
        blockRawDataBO.setParentHash(block.getParentHash());
        blockRawDataBO.setReceiptsRoot(block.getReceiptsRoot());
        blockRawDataBO.setSealer(block.getSealer());
        blockRawDataBO.setSealerList(JacksonUtils.toJson(block.getSealerList()));
        blockRawDataBO.setSignatureList(JacksonUtils.toJson(block.getSignatureList()));
        blockRawDataBO.setStateRoot(block.getStateRoot());
        blockRawDataBO.setTransactionsRoot(block.getTransactionsRoot());
        blockRawDataBO.setTransactionList(JacksonUtils.toJson(block.getTransactions()));
        blockRawDataBO.setBlockObject(JacksonUtils.toJson(block));
        return blockRawDataBO;
    }
}
