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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.webank.blockchain.data.export.core.DataBeeApplicationTests;
import org.fisco.bcos.sdk.abi.FunctionReturnDecoder;
import org.fisco.bcos.sdk.abi.TypeReference;
import org.fisco.bcos.sdk.abi.Utils;
import org.fisco.bcos.sdk.abi.datatypes.Type;
import org.fisco.bcos.sdk.abi.datatypes.generated.Uint64;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.TransactionResult;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import com.webank.blockchain.data.export.extractor.ods.EthClient;

import lombok.extern.slf4j.Slf4j;

/**
 * 
 * BlockInfoServiceTest
 *
 * @Description: BlockInfoServiceTest
 * @author graysonzhang
 * @data 2018-11-14 15:15:17
 *
 */
@Slf4j
public class BlockInfoServiceTest extends DataBeeApplicationTests {

    @Autowired
    private EthClient ethClient;
    @Autowired
    private Client web3j;

    @Test
    public void testInput() throws IOException {
        Block block = ethClient.getBlock(BigInteger.valueOf(8677));
        List<TransactionResult> transactionResults = block.getTransactions();
        log.info("transactionResults.size:{}", transactionResults.size());
        for (TransactionResult result : transactionResults) {
            BcosTransactionReceipt ethGetTransactionReceipt = web3j.getTransactionReceipt((String) result.get());
            Optional<TransactionReceipt> opt = ethGetTransactionReceipt.getTransactionReceipt();
            if (opt.isPresent()) {
                log.info("TransactionReceipt hash: {}", opt.get().getTransactionHash());
                Optional<JsonTransactionResponse> optt =
                        web3j.getTransactionByHash(opt.get().getTransactionHash()).getTransaction();
                if (optt.isPresent()) {
                    log.info("transaction hash : {}", optt.get().getHash());
                    log.info("transaction info : {}", optt.get().getValue());
                    List<Type> lt = new ArrayList<>();
                    lt.add(Uint64.DEFAULT);
                    List<TypeReference<?>> references = new ArrayList<>();
                    TypeReference<Uint64> typeReference = new TypeReference<Uint64>() {
                    };
                    references.add(typeReference);
                    List<TypeReference<Type>> ll = Utils.convert(references);
                    List<Type> inputList = FunctionReturnDecoder.decode(optt.get().getInput(), ll);
                    log.info("input : {}", inputList.size());
                    log.info("input : {}", JacksonUtils.toJson(inputList));
                }

            }
        }

    }

}
