/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.db.vo;

import java.util.List;

import javax.validation.constraints.Pattern;

import org.springframework.data.domain.Page;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * CommonPageRes
 *
 * @author maojiayu
 * @data Dec 19, 2018 11:40:34 PM
 *
 */
@Data
@NoArgsConstructor
@Accessors(chain = true)
public class CommonPageRes<T> {
    /** @Fields pageNo : request page index, start from 1. */
    private int pageNo = 1;
    /** @Fields pageSize : requst size of one page */
    private int pageSize = 20;
    /** @Fields totalCount : total items count */
    private long totalCount = 0L;
    /** @Fields orderBy : order by which field. */
    private String orderBy = "blockTimeStamp";
    @Pattern(regexp = "DESC|ASC")
    private String order = "DESC"; // ASC or DESC
    private List<T> result;

    public CommonPageRes(CommonPageReq req, Page page) {
        this(req);
        this.totalCount = page.getTotalElements();
    }

    public CommonPageRes(CommonPageReq p) {
        this.pageNo = p.getPageNo();
        this.pageSize = p.getPageSize();
        this.orderBy = p.getOrderBy();
        this.order = p.getOrder();
    }

}
