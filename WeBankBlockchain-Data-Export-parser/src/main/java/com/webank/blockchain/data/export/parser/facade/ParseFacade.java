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

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import com.webank.blockchain.data.export.common.bo.data.BlockContractInfoBO;
import com.webank.blockchain.data.export.parser.handler.MethodCrawlerHandler;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.base.Stopwatch;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.BlockMethodInfo;
import com.webank.blockchain.data.export.parser.handler.BlockCrawlerHandler;
import com.webank.blockchain.data.export.parser.handler.ContractCrawlerHandler;
import com.webank.blockchain.data.export.parser.handler.EventCrawlerHandler;

import lombok.extern.slf4j.Slf4j;

/**
 * ParseFacade
 *
 * @Description: ParseFacade
 * @author maojiayu
 * @data Jul 3, 2019 11:04:14 AM
 *
 */
@Service
@Slf4j
public class ParseFacade implements ParseInterface {
    @Autowired
    private ContractCrawlerHandler contractCrawlerHandler;
    @Autowired
    private BlockCrawlerHandler blockCrawlerHandler;
    @Autowired
    private EventCrawlerHandler eventCrawlHandler;
    @Autowired
    private MethodCrawlerHandler methodCrawlerHandler;

    /*
     * dependency: P1) getAccounts-> Accounts. P2) depend on 1, txHashContractAddress(in order to get method address) ->
     * methods. P3) depend on 2, txHashContractName.
     */
    @Override
    public BlockInfoBO parse(Block block) throws IOException {
        BlockInfoBO blockInfo = new BlockInfoBO();
        Stopwatch st = Stopwatch.createStarted();
        BlockContractInfoBO contractInfoBO = contractCrawlerHandler.crawl(block);
        log.debug("Block {} , Account crawler handle useTime {} ", block.getNumber(),
                st.stop().elapsed(TimeUnit.MILLISECONDS));
        st.start();
        BlockMethodInfo blockMethodInfo =
                methodCrawlerHandler.crawl(block, contractInfoBO.getTxHashContractAddressMapping());
        log.debug("Block {} , method crawler handle useTime {} ", block.getNumber(),
                st.stop().elapsed(TimeUnit.MILLISECONDS));
        st.start();
        blockInfo.setDeployedAccountInfoBOS(contractInfoBO.getDeployedAccountInfoBOS())
                .setBlockDetailInfo(blockCrawlerHandler.handleBlockDetail(block))
                .setBlockRawDataBO(blockCrawlerHandler.handleBlockRawData(block))
                .setEventInfoList(eventCrawlHandler.crawl(block, blockMethodInfo.getTxHashContractNameMapping()))
                .setMethodInfoList(blockMethodInfo.getMethodInfoList())
                .setBlockTxDetailInfoList(blockMethodInfo.getBlockTxDetailInfoList())
                .setTxRawDataBOList(blockMethodInfo.getTxRawDataBOList())
                .setTxReceiptRawDataBOList(blockMethodInfo.getTxReceiptRawDataBOList());
        log.debug("Block {} , event crawler handle useTime {} ", block.getNumber(),
                st.stop().elapsed(TimeUnit.MILLISECONDS));
        return blockInfo;
    }

}
