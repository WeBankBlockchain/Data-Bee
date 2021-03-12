package com.webank.blockchain.data.export.common.entity;

import lombok.Builder;
import lombok.Data;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/17
 */
@Data
@Builder
public class MysqlDataSource {

    private String jdbcUrl;
    private String user;
    private String pass;
}
