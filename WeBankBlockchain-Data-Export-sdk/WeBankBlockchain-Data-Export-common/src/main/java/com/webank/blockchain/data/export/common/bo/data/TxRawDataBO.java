package com.webank.blockchain.data.export.common.bo.data;

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
public class TxRawDataBO {

    private long blockHeight;

    private String blockHash;

    private String txHash;

    private String txIndex;

    private Date blockTimeStamp;

    private String from;
    private String gas;
    private String input;
    private String nonce;
    private String to;
    private String value;
    private String gasPrice;

}
