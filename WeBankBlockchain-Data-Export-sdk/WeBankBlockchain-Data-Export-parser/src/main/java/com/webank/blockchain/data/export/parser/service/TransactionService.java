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
package com.webank.blockchain.data.export.parser.service;

import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.bo.contract.MethodMetaInfo;
import com.webank.blockchain.data.export.common.constants.ContractConstants;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * TransactionService
 *
 * @Description: TransactionService
 * @author maojiayu
 * @data Jul 23, 2019 10:15:46 AM
 *
 */
@Slf4j
public class TransactionService {



    public static String getContractAddressByTransaction(JsonTransactionResponse transaction,
                                                  Map<String, String> txHashContractAddressMapping) {
        log.debug("blocknumber: {} , to: {}, map: {}", transaction.getBlockNumber(), transaction.getTo(),
                JacksonUtils.toJson(txHashContractAddressMapping));
        if (transaction.getTo() == null || transaction.getTo().equals(ContractConstants.EMPTY_ADDRESS)) {
            return txHashContractAddressMapping.get(transaction.getHash());
        } else {
            return transaction.getTo();
        }
    }

    public static Optional<String> getContractNameByTransaction(JsonTransactionResponse transaction,
                                                         Map<String, String> txHashContractAddressMapping) throws IOException {
        String contractAddress = getContractAddressByTransaction(transaction, txHashContractAddressMapping);
        if (StringUtils.isEmpty(contractAddress)) {
            log.warn(
                    "block:{} , unrecognized transaction, maybe the contract is not registered! See the DIR of contractPath.",
                    transaction.getBlockNumber());
            return Optional.empty();
        }
        String input = ExportConstant.getCurrentContext().getClient().getCode(contractAddress).getCode();
        log.debug("code: {}", JacksonUtils.toJson(input));
        Map.Entry<String, ContractDetail> contractEntry = ContractConstructorService.getConstructorNameByCode(input);
        if (contractEntry == null) {
            log.warn(
                    "block:{} constructor code can't be find, maybe the contract is not registered! See the DIR of contractPath.",
                    transaction.getBlockNumber());
            return Optional.empty();
        }
        log.debug("Block{} contractAddress{} transactionInput: {}", transaction.getBlockNumber(), contractAddress,
                transaction.getInput());
        return Optional.of(contractEntry.getValue().getContractInfoBO().getContractName());
    }


    public static MethodMetaInfo getMethodMetaInfo(JsonTransactionResponse transaction, String contractName) {
        ContractMapsInfo contractMapsInfo = ContractConstants.getCurrentContractMaps();
//        if (transaction.getTo() == null || transaction.getTo().equals(ContractConstants.EMPTY_ADDRESS)) {
//            MethodMetaInfo methodMetaInfo = new MethodMetaInfo();
//            methodMetaInfo.setContractName(contractName).setMethodName("constructor");
//            return methodMetaInfo;
//        }
        String methodTag = transaction.getInput().substring(0, 10) + "_" +contractName;
        if (transaction.getInput() != null && contractMapsInfo.getMethodIdMap().containsKey(methodTag)) {
            return contractMapsInfo.getMethodIdMap().get(methodTag);

        } else {
            return null;
        }
    }
}
