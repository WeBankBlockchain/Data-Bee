package com.webank.blockchain.data.export.parser.contract;

import cn.hutool.core.collection.CollectionUtil;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.bo.contract.MethodMetaInfo;
import com.webank.blockchain.data.export.common.bo.data.ContractInfoBO;
import com.webank.blockchain.data.export.common.constants.ContractConstants;
import com.webank.blockchain.data.export.common.entity.ContractInfo;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.crypto.hash.Keccak256;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/25
 */
@Slf4j
public class ContractParser {

    public static ContractMapsInfo initContractMaps(List<ContractInfo> contractInfoList){
        if (CollectionUtil.isEmpty(contractInfoList)){
            return null;
        }
        ContractMapsInfo contractMapsInfo = new ContractMapsInfo();
        Map<String, MethodMetaInfo> methodIdMap = new HashMap<>();
        Map<String, ContractDetail> contractBinaryMap = new HashMap<>();
        contractMapsInfo.setContractBinaryMap(contractBinaryMap);
        contractMapsInfo.setMethodIdMap(methodIdMap);
        for (ContractInfo entry : contractInfoList) {
            ContractDetail contractDetail = new ContractDetail();
            ContractInfoBO contractInfoBO = new ContractInfoBO();
            String abi = entry.getAbi();
            if (abi == null) {
                log.error("abi is null !!! please set it");
            }
            String binary = entry.getBinary();
            if (binary == null) {
                log.error("binary is null !!! please set it");
            }
            contractInfoBO.setContractABI(abi);
            contractInfoBO.setAbiHash(new Keccak256().hash(abi));
            contractInfoBO.setContractBinary(binary);
            contractInfoBO.setContractName(entry.getContractName());
            contractDetail.setContractInfoBO(contractInfoBO);
            contractDetail.setMethodMetaInfos(MethodParser.parseToInfoList(abi,entry.getContractName()));
            contractDetail.setEventMetaInfos(EventParser.parseToInfoList(abi,entry.getContractName()));
            for (MethodMetaInfo methodMetaInfo : contractDetail.getMethodMetaInfos()) {
                methodIdMap.put(methodMetaInfo.getMethodId(), methodMetaInfo);
                contractBinaryMap.put(binary, contractDetail);
            }
        }
        return contractMapsInfo;
    }
}
