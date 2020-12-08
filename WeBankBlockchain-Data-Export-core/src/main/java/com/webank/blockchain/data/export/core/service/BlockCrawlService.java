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
package com.webank.blockchain.data.export.core.service;

import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import com.webank.blockchain.data.export.extractor.ods.EthClient;
import com.webank.blockchain.data.export.parser.facade.ParseInterface;

import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.base.Stopwatch;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;

import lombok.extern.slf4j.Slf4j;

/**
 * BlockCrawlService
 *
 * @Description: BlockCrawlService
 * @author maojiayu
 * @data 2019-07-05 16:06:12
 *
 */
@Service
@Slf4j
public class BlockCrawlService {
    @Autowired
    private EthClient ethClient;
    @Autowired
    private ParseInterface parser;

    /**
     * parse a Block to BlockInfoBO by using parser tools.
     * 
     * @param blockHeight
     * @return BlockInfoBO, which include all the structs of a block containing contract info.
     * @throws IOException
     */
    public BlockInfoBO parse(long blockHeight) throws IOException {
        BigInteger bigBlockHeight = new BigInteger(Long.toString(blockHeight));
        Block block = ethClient.getBlock(bigBlockHeight);
        return parse(block);
    }

    public BlockInfoBO parse(Block block) throws IOException {
        Stopwatch st1 = Stopwatch.createStarted();
        BlockInfoBO blockInfo = parser.parse(block);
        log.info("bcosCrawlerMap block:{} succeed, bcosCrawlerMap.handleReceipt useTime: {}",
                block.getNumber().longValue(), st1.stop().elapsed(TimeUnit.MILLISECONDS));
        return blockInfo;
    }

}
