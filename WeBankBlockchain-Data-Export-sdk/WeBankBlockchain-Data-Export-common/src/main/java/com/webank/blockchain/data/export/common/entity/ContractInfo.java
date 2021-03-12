package com.webank.blockchain.data.export.common.entity;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/25
 */
@Data
@Accessors(chain = true)
public class ContractInfo {

    private String contractName;

    private String abi;

    private String binary;

    private short version;

}
