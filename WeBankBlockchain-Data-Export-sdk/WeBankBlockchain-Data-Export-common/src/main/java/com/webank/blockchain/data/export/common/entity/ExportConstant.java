package com.webank.blockchain.data.export.common.entity;


import cn.hutool.db.DbUtil;
import cn.hutool.log.level.Level;
import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/16
 */
public class ExportConstant {

    static {
        DbUtil.setShowSqlGlobal(true,false,true, Level.INFO);
    }

    public static final ThreadLocal<DataExportContext> context = new ThreadLocal<>();

    public static DataExportContext getCurrentContext() {
        return context.get();
    }

    public static void setCurrentContext(DataExportContext currentContext) {
        context.set(currentContext);
    }

    public static final String BLOCK_TASK_POOL_DAO = "block_task_pool_dao";

    public static final String BLOCK_DETAIL_DAO = "block_detail_info_dao";

    public static final String BLOCK_RAW_DAO = "block_raw_data_dao";

    public static final String BLOCK_TX_DETAIL_DAO = "block_tx_detail_info_dao";

    public static final String TX_RAW_DAO = "tx_raw_data_dao";

    public static final String TX_RECEIPT_RAW_DAO = "tx_receipt_raw_data_dao";

    public static final String DEPLOYED_ACCOUNT_DAO = "deployed_account_info_dao";

    public static final String CONTRACT_INFO_DAO = "contract_info_dao";

    public static final String BLOCK_DETAIL_INFO_TABLE = "block_detail_info";

    public static final String BLOCK_TASK_POOL_TABLE = "block_task_pool";

    public static final String BLOCK_RAW_DATA_TABLE = "block_raw_data";

    public static final String BLOCK_TX_DETAIL_INFO_TABLE = "block_tx_detail_info";

    public static final String DEPLOYED_ACCOUNT_INFO_TABLE = "deployed_account_info";

    public static final String TX_RAW_DATA_TABLE = "tx_raw_data";

    public static final String TX_RECEIPT_RAW_DATA_TABLE = "tx_receipt_raw_data";

    public static final String CONTRACT_INFO_TABLE = "contract_info";

    public static final List<String> tables = Lists.newArrayList(
            BLOCK_DETAIL_INFO_TABLE,
            BLOCK_TASK_POOL_TABLE,
            BLOCK_RAW_DATA_TABLE,
            BLOCK_TX_DETAIL_INFO_TABLE,
            DEPLOYED_ACCOUNT_INFO_TABLE,
            TX_RAW_DATA_TABLE,
            TX_RECEIPT_RAW_DATA_TABLE,
            CONTRACT_INFO_TABLE);
}
