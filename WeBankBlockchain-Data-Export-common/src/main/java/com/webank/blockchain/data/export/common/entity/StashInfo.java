package com.webank.blockchain.data.export.common.entity;


import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/3/3
 */

@EqualsAndHashCode(callSuper = true)
@Data
@Builder
public class StashInfo extends BlockDataSource {
    private String jdbcUrl;
    private String user;
    private String pass;
    private int cryptoTypeConfig;
}
