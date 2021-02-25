package com.webank.blockchain.data.export.common.entity;

import cn.hutool.core.util.StrUtil;
import com.webank.blockchain.data.export.common.bo.contract.EventMetaInfo;
import com.webank.blockchain.data.export.common.bo.contract.FieldVO;
import com.webank.blockchain.data.export.common.bo.contract.MethodMetaInfo;

import java.util.HashMap;
import java.util.Map;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/18
 */
public class TableSQL {

    public static Map<String, String> tableSqlMap;

    public static String BLOCK_DETAIL_INFO = "CREATE TABLE `block_detail_info` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `block_hash` varchar(255) DEFAULT NULL,\n" +
            "  `block_height` bigint(20) DEFAULT NULL,\n" +
            "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  `status` smallint(6) NOT NULL,\n" +
            "  `tx_count` smallint(6) DEFAULT NULL,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  UNIQUE KEY `UK_block_height` (`block_height`),\n" +
            "  KEY `block_hash` (`block_hash`),\n" +
            "  KEY `block_timestamp` (`block_time_stamp`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";
    public static final String BLOCK_RAW_DATA = " CREATE TABLE `block_raw_data` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `block_hash` varchar(255) DEFAULT NULL,\n" +
            "  `block_height` bigint(20) DEFAULT NULL,\n" +
            "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
            "  `db_hash` varchar(255) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  `extra_data` longtext,\n" +
            "  `gas_limit` varchar(255) DEFAULT NULL,\n" +
            "  `gas_used` varchar(255) DEFAULT NULL,\n" +
            "  `logs_bloom` longtext,\n" +
            "  `parent_hash` varchar(255) DEFAULT NULL,\n" +
            "  `receipts_root` varchar(255) DEFAULT NULL,\n" +
            "  `sealer` varchar(255) DEFAULT NULL,\n" +
            "  `sealer_list` longtext,\n" +
            "  `signature_list` longtext,\n" +
            "  `state_root` varchar(255) DEFAULT NULL,\n" +
            "  `transaction_list` longtext,\n" +
            "  `transactions_root` varchar(255) DEFAULT NULL,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  UNIQUE KEY `UK_block_height` (`block_height`),\n" +
            "  KEY `block_hash` (`block_hash`),\n" +
            "  KEY `block_timestamp` (`block_time_stamp`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";

    public static final String BLOCK_TASK_POOL = "CREATE TABLE `block_task_pool` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `block_height` bigint(20) DEFAULT NULL,\n" +
            "  `certainty` smallint(6) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  `handle_item` smallint(6) DEFAULT NULL,\n" +
            "  `sync_status` smallint(6) DEFAULT NULL,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  UNIQUE KEY `UK_block_height` (`block_height`),\n" +
            "  KEY `sync_status` (`sync_status`),\n" +
            "  KEY `certainty` (`certainty`),\n" +
            "  KEY `depot_updatetime` (`depot_updatetime`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";

    public static final String BLOCK_TX_DETAIL_INFO = "CREATE TABLE `block_tx_detail_info` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `block_hash` varchar(255) DEFAULT NULL,\n" +
            "  `block_height` bigint(20) DEFAULT NULL,\n" +
            "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
            "  `contract_name` varchar(255) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  `method_name` varchar(255) DEFAULT NULL,\n" +
            "  `tx_from` varchar(255) DEFAULT NULL,\n" +
            "  `tx_hash` varchar(255) DEFAULT NULL,\n" +
            "  `tx_to` varchar(255) DEFAULT NULL,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  KEY `block_height` (`block_height`),\n" +
            "  KEY `tx_from` (`tx_from`),\n" +
            "  KEY `block_timestamp` (`block_time_stamp`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";
    public static final String DEPLOYED_ACCOUNT_INFO = "CREATE TABLE `deployed_account_info` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `abi_hash` varchar(255) DEFAULT NULL,\n" +
            "  `block_height` bigint(20) DEFAULT NULL,\n" +
            "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
            "  `contract_address` varchar(255) DEFAULT NULL,\n" +
            "  `contract_name` varchar(255) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  KEY `block_height` (`block_height`),\n" +
            "  KEY `contract_address` (`contract_address`),\n" +
            "  KEY `block_timestamp` (`block_time_stamp`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";
    public static final String TX_RAW_DATA = "CREATE TABLE `tx_raw_data` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `block_hash` varchar(255) DEFAULT NULL,\n" +
            "  `block_height` bigint(20) DEFAULT NULL,\n" +
            "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  `from` varchar(255) DEFAULT NULL,\n" +
            "  `gas` varchar(255) DEFAULT NULL,\n" +
            "  `gas_price` varchar(255) DEFAULT NULL,\n" +
            "  `input` longtext,\n" +
            "  `nonce` varchar(255) DEFAULT NULL,\n" +
            "  `to` varchar(255) DEFAULT NULL,\n" +
            "  `tx_hash` varchar(255) DEFAULT NULL,\n" +
            "  `tx_index` varchar(255) DEFAULT NULL,\n" +
            "  `value` varchar(255) DEFAULT NULL,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  KEY `block_hash` (`block_hash`),\n" +
            "  KEY `block_timestamp` (`block_time_stamp`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";
    public static final String TX_RECEIPT_RAW_DATA = "CREATE TABLE `tx_receipt_raw_data` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `block_hash` varchar(255) DEFAULT NULL,\n" +
            "  `block_height` bigint(20) DEFAULT NULL,\n" +
            "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
            "  `contract_address` varchar(255) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  `from` varchar(255) DEFAULT NULL,\n" +
            "  `gas_used` varchar(255) DEFAULT NULL,\n" +
            "  `input` longtext,\n" +
            "  `logs` longtext,\n" +
            "  `logs_bloom` longtext,\n" +
            "  `message` varchar(255) DEFAULT NULL,\n" +
            "  `output` longtext,\n" +
            "  `receipt_proof` longtext,\n" +
            "  `root` varchar(255) DEFAULT NULL,\n" +
            "  `status` varchar(255) DEFAULT NULL,\n" +
            "  `to` varchar(255) DEFAULT NULL,\n" +
            "  `tx_hash` varchar(255) DEFAULT NULL,\n" +
            "  `tx_index` varchar(255) DEFAULT NULL,\n" +
            "  `tx_proof` longtext,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  KEY `block_hash` (`block_hash`),\n" +
            "  KEY `block_timestamp` (`block_time_stamp`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";

    public static final String CONTRACT_INFO = "CREATE TABLE `contract_info` (\n" +
            "  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
            "  `abi_hash` varchar(255) DEFAULT NULL,\n" +
            "  `contract_abi` longtext,\n" +
            "  `contract_binary` longtext,\n" +
            "  `contract_name` varchar(255) DEFAULT NULL,\n" +
            "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
            "  `version` smallint(6) DEFAULT NULL,\n" +
            "  PRIMARY KEY (`pk_id`),\n" +
            "  UNIQUE KEY `abi_hash` (`abi_hash`)\n" +
            ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";

    public static final String TABLE_POSTFIX =
            "  PRIMARY KEY (`pk_id`),\n" +
                    "  KEY `block_height` (`block_height`),\n" +
                    "  KEY `block_timestamp` (`block_time_stamp`),\n" +
                    "  KEY `tx_hash` (`tx_hash`)\n" +
                    ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;";

    public static String getTableName(String contractName,String name){
        ExportConfig config = ExportConstant.getCurrentContext().getConfig();
        String tablePrefix = config.getTablePrefix();
        String tablePostfix = config.getTablePostfix();
        return tablePrefix + contractName + "_" + StrUtil.toUnderlineCase(name) + tablePostfix;
    }


    public static String createMethodTableSql(MethodMetaInfo methodMetaInfo) {
        StringBuilder sql = new StringBuilder();
        sql.append("CREATE TABLE ")
                .append("`").append(getTableName(methodMetaInfo.getContractName(), methodMetaInfo.getMethodName()))
                .append("`")
                .append(" (\n")
                .append("  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
                        "  `block_height` bigint(20) DEFAULT NULL,\n" +
                        "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
                        "  `contract_address` varchar(255) DEFAULT NULL,\n" +
                        "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
                        "  `method_status` varchar(255) DEFAULT NULL,\n" +
                        "  `tx_hash` varchar(255) DEFAULT NULL,\n");
        for (FieldVO fieldVO : methodMetaInfo.getFieldsList()) {
            sql.append("`").append(fieldVO.getSqlName()).append("` ")
                    .append(fieldVO.getSqlType())
                    .append(" DEFAULT NULL,\n");
        }
        for (FieldVO fieldVO : methodMetaInfo.getOutputList()) {
            sql.append("`").append(fieldVO.getSqlName()).append("` ")
                    .append(fieldVO.getSqlType())
                    .append(" DEFAULT NULL,\n");
        }
        sql.append(TABLE_POSTFIX);
        return sql.toString();
    }


    public static String createEventTableSql(EventMetaInfo eventMetaInfo) {
        StringBuilder sql = new StringBuilder();
        sql.append("CREATE TABLE ").append("`").append(
                 getTableName(eventMetaInfo.getContractName(), eventMetaInfo.getEventName()))
                .append("`")
                .append(" (\n")
                .append("  `pk_id` bigint(20) NOT NULL AUTO_INCREMENT,\n" +
                        "  `block_height` bigint(20) DEFAULT NULL,\n" +
                        "  `block_time_stamp` datetime(6) DEFAULT NULL,\n" +
                        "  `contract_address` varchar(255) DEFAULT NULL,\n" +
                        "  `depot_updatetime` datetime(6) DEFAULT NULL,\n" +
                        "  `tx_hash` varchar(255) DEFAULT NULL,\n");
        for (FieldVO fieldVO : eventMetaInfo.getList()) {
            sql.append("`").append(fieldVO.getSqlName()).append("` ")
                    .append(fieldVO.getSqlType())
                    .append(" DEFAULT NULL,\n");
        }
        sql.append(TABLE_POSTFIX);
        return sql.toString();
    }

    static {
        tableSqlMap = new HashMap<>();
        tableSqlMap.put("block_detail_info", BLOCK_DETAIL_INFO);
        tableSqlMap.put("block_raw_data", BLOCK_RAW_DATA);
        tableSqlMap.put("block_task_pool", BLOCK_TASK_POOL);
        tableSqlMap.put("block_tx_detail_info", BLOCK_TX_DETAIL_INFO);
        tableSqlMap.put("deployed_account_info", DEPLOYED_ACCOUNT_INFO);
        tableSqlMap.put("tx_receipt_raw_data", TX_RECEIPT_RAW_DATA);
        tableSqlMap.put("tx_raw_data", TX_RAW_DATA);
        tableSqlMap.put("contract_info",CONTRACT_INFO);
    }
}
