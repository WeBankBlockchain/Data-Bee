package com.webank.blockchain.data.export.common.enums;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.collection.ListUtil;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/23
 */
@AllArgsConstructor
@Getter
public enum DataType {

    NULL("null"),
    BLOCK_DETAIL_INFO_TABLE("block_detail_info"),
    BLOCK_RAW_DATA_TABLE("block_raw_data"),
    BLOCK_TX_DETAIL_INFO_TABLE("block_tx_detail_info"),
    TX_RAW_DATA_TABLE("tx_raw_data"),
    TX_RECEIPT_RAW_DATA_TABLE("tx_receipt_raw_data"),
    DEPLOYED_ACCOUNT_INFO_TABLE("deployed_account_info"),
    CONTRACT_INFO_TABLE("contract_info"),
    EVENT_TABLE("event"),
    METHOD_TABLE("method");


    private String tableName;

    public static List<DataType> getDefault(){
        return ListUtil.toList(NULL);
    }

    public static List<String> getTables(List<DataType> dataTypes){
        if (CollectionUtil.isEmpty(dataTypes)) {
            return Collections.emptyList();
        }
        return dataTypes.stream().map(DataType::getTableName).collect(Collectors.toList());
    }


}
