package com.webank.blockchain.data.export.common.bo.data;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;
import org.fisco.bcos.sdk.model.MerkleProofUnit;
import org.fisco.bcos.sdk.model.TransactionReceipt;

import java.util.Date;
import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TxReceiptRawDataBO {

    private long blockHeight;

    private String blockHash;

    private String txHash;

    private Date blockTimeStamp;

    private String txIndex;
    private String root;
    private String from;
    private String to;
    private String gasUsed;
    private String contractAddress;
    private String logs;
    private String logsBloom;
    private String status;
    private String input;
    private String output;
    private String txProof;
    private String receiptProof;
    private String message;
}
