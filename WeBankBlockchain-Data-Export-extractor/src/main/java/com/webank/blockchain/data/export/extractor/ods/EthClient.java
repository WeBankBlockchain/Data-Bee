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
package com.webank.blockchain.data.export.extractor.ods;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import com.google.common.base.Stopwatch;
import com.webank.blockchain.data.export.common.aspect.Retry;

import lombok.extern.slf4j.Slf4j;

/**
 * EthClient
 *
 * @Description: EthClient
 * @author maojiayu
 * @date 2018年11月13日 下午2:44:21
 * 
 */
@Service
@Slf4j
public class EthClient {
    @Autowired
    private Client client;

    @Cacheable(cacheNames = { "block" })
    @Retry
    public Block getBlock(BigInteger blockHeightNumber) throws IOException {
        Stopwatch stopwatch = Stopwatch.createStarted();
        log.debug("get block number: {}", blockHeightNumber);
        Block block = client.getBlockByNumber(blockHeightNumber, true).getBlock();
        Stopwatch st1 = stopwatch.stop();
        log.info("get block:{} succeed, eth.getBlock useTime: {}", blockHeightNumber,
                st1.elapsed(TimeUnit.MILLISECONDS));
        return block;
    }


    @Cacheable(cacheNames = { "transactionReceipt" })
    public BcosTransactionReceipt getTransactionReceipt(String hash) throws IOException {
        return client.getTransactionReceipt(hash);
    }

    public Optional<JsonTransactionResponse> getTransactionByHash(TransactionReceipt receipt) throws IOException {
        return client.getTransactionByHash(receipt.getTransactionHash()).getTransaction();

    }

    @Cacheable(cacheNames = { "code" })
    public String getCodeByContractAddress(String contractAddress) throws IOException {
        return client.getCode(contractAddress).getCode();
    }
}
