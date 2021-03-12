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
package com.webank.blockchain.data.export.parser.facade;

import com.google.common.base.Stopwatch;
import com.webank.blockchain.data.export.common.bo.data.BlockContractInfoBO;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.BlockMethodInfo;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.enums.DataType;
import com.webank.blockchain.data.export.parser.handler.BlockCrawlerHandler;
import com.webank.blockchain.data.export.parser.handler.ContractCrawlerHandler;
import com.webank.blockchain.data.export.parser.handler.EventCrawlerHandler;
import com.webank.blockchain.data.export.parser.handler.MethodCrawlerHandler;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * ParseFacade
 *
 * @Description: ParseFacade
 * @author maojiayu
 * @data Jul 3, 2019 11:04:14 AM
 *
 */
@Slf4j
public class ParseFacade {

    /*
     * dependency: P1) getAccounts-> Accounts. P2) depend on 1, txHashContractAddress(in order to get method address) ->
     * methods. P3) depend on 2, txHashContractName.
     */
    public static BlockInfoBO parse(Block block) throws IOException {
        BlockInfoBO blockInfo = new BlockInfoBO();
        Stopwatch st = Stopwatch.createStarted();
        BlockContractInfoBO contractInfoBO = ContractCrawlerHandler.crawl(block);
        log.debug("Block {} , Account crawler handle useTime {} ", block.getNumber(),
                st.stop().elapsed(TimeUnit.MILLISECONDS));
        st.start();
        BlockMethodInfo blockMethodInfo =
                MethodCrawlerHandler.crawl(block, contractInfoBO.getTxHashContractAddressMapping());

        log.debug("Block {} , method crawler handle useTime {} ", block.getNumber(),
                st.stop().elapsed(TimeUnit.MILLISECONDS));
        st.start();
        List<DataType> blackList = ExportConstant.getCurrentContext().getConfig().getDataTypeBlackList();
        if (!blackList.contains(DataType.BLOCK_DETAIL_INFO_TABLE)){
            blockInfo.setBlockDetailInfo(BlockCrawlerHandler.handleBlockDetail(block));
        }
        if (!blackList.contains(DataType.DEPLOYED_ACCOUNT_INFO_TABLE)){
            blockInfo.setDeployedAccountInfoBOS(contractInfoBO.getDeployedAccountInfoBOS());
        }
        if (!blackList.contains(DataType.BLOCK_RAW_DATA_TABLE)){
            blockInfo.setBlockRawDataBO(BlockCrawlerHandler.handleBlockRawData(block));
        }
        if (!blackList.contains(DataType.BLOCK_TX_DETAIL_INFO_TABLE)){
            blockInfo.setBlockTxDetailInfoList(blockMethodInfo.getBlockTxDetailInfoList());
        }
        if (!blackList.contains(DataType.TX_RAW_DATA_TABLE)){
            blockInfo.setTxRawDataBOList(blockMethodInfo.getTxRawDataBOList());
        }
        if (!blackList.contains(DataType.TX_RECEIPT_RAW_DATA_TABLE)){
            blockInfo.setTxReceiptRawDataBOList(blockMethodInfo.getTxReceiptRawDataBOList());
        }
        if (!blackList.contains(DataType.EVENT_TABLE)){
            blockInfo.setEventInfoList(EventCrawlerHandler.crawl(block, blockMethodInfo.getTxHashContractNameMapping()));
        }
        if (!blackList.contains(DataType.METHOD_TABLE)){
            blockInfo.setMethodInfoList(blockMethodInfo.getMethodInfoList());
        }

        log.debug("Block {} , event crawler handle useTime {} ", block.getNumber(),
                st.stop().elapsed(TimeUnit.MILLISECONDS));
        return blockInfo;
    }

}
