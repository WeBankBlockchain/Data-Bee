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

import com.webank.blockchain.data.export.extractor.ods.EthClient;
import com.webank.blockchain.data.export.parser.service.ContractConstructorService;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.data.BlockContractInfoBO;
import com.webank.blockchain.data.export.common.bo.data.DeployedAccountInfoBO;
import com.webank.blockchain.data.export.common.constants.ContractConstants;
import com.webank.blockchain.data.export.common.tools.DateUtils;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.utils.Numeric;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Service
@EnableScheduling
@Slf4j
public class ContractCrawlerHandler {

    @Autowired
    private EthClient ethClient;

    /** @Fields contractConstructorService : contract constructor service */
    @Autowired
    private ContractConstructorService contractConstructorService;


    @SuppressWarnings("rawtypes")
    public BlockContractInfoBO crawl(BcosBlock.Block block) throws IOException {
        List<DeployedAccountInfoBO> deployedAccountInfoBOList = new ArrayList<>();
        Map<String, String> map = new HashMap<>();
        List<BcosBlock.TransactionResult> transactionResults = block.getTransactions();
        for (BcosBlock.TransactionResult result : transactionResults) {
            BcosBlock.TransactionObject to = (BcosBlock.TransactionObject) result;
            JsonTransactionResponse transaction = to.get();
            BcosTransactionReceipt bcosTransactionReceipt = ethClient.getTransactionReceipt(transaction.getHash());
            Optional<TransactionReceipt> opt = bcosTransactionReceipt.getTransactionReceipt();
            if (opt.isPresent()) {
                TransactionReceipt tr = opt.get();

                handle(tr, DateUtils.hexStrToDate(block.getTimestamp())).ifPresent(e -> {
                    deployedAccountInfoBOList.add(e);
                    map.putIfAbsent(e.getTxHash(), e.getContractAddress());
                });

            }
        }
        return new BlockContractInfoBO(map,deployedAccountInfoBOList);
    }

    public Optional<DeployedAccountInfoBO> handle(TransactionReceipt receipt, Date blockTimeStamp) throws IOException {
        Optional<JsonTransactionResponse> optt = ethClient.getTransactionByHash(receipt);
        if (optt.isPresent()) {
            JsonTransactionResponse transaction = optt.get();
            // get constructor function transaction by judging if transaction's param named to is null
            if (transaction.getTo() == null || transaction.getTo().equals(ContractConstants.EMPTY_ADDRESS)) {
                String contractAddress = receipt.getContractAddress();
                String input = ethClient.getCodeByContractAddress(contractAddress);
                log.debug("blockNumber: {}, input: {}", receipt.getBlockNumber(), input);
                Map.Entry<String, ContractDetail> entry = contractConstructorService.getConstructorNameByCode(input);
                if (entry == null) {
                    log.info("block:{} constructor binary can't find!", receipt.getBlockNumber());
                    return Optional.empty();
                }
                DeployedAccountInfoBO deployedAccountInfoBO = new DeployedAccountInfoBO();
                deployedAccountInfoBO.setBlockTimeStamp(blockTimeStamp)
                        .setBlockHeight(Numeric.toBigInt(receipt.getBlockNumber()).longValue())
                        .setContractAddress(receipt.getContractAddress())
                        .setContractName(entry.getValue().getContractInfoBO().getContractName())
                        .setBinary(entry.getValue().getContractInfoBO().getContractBinary())
                        .setTxHash(receipt.getTransactionHash());
                return Optional.of(deployedAccountInfoBO);
            }
        }
        return Optional.empty();
    }
}
