package com.webank.blockchain.data.export.common.bo.data;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Date;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DeployedAccountInfoBO {

    private String contractName;

    private String contractAddress;

    private long blockHeight;

    private Date blockTimeStamp;

    private String abiHash;

    private String txHash;

    private String binary;
}
