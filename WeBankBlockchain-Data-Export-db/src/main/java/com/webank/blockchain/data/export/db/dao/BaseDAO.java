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
package com.webank.blockchain.data.export.db.dao;

import java.util.Collection;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import org.springframework.data.repository.CrudRepository;

import com.google.common.base.Stopwatch;

import lombok.extern.slf4j.Slf4j;

/**
 * BaseDAO supports to count the time of certain operation.
 *
 * @author maojiayu
 * @data Dec 13, 2018 9:40:57 PM
 *
 */
@Slf4j
public class BaseDAO {

    public static <T, U> void saveWithTimeLog(BiConsumer<T, U> bi, T t, U u) {
        Stopwatch st = Stopwatch.createStarted();
        bi.accept(t, u);
        Stopwatch st1 = st.stop();
        log.debug("{} save succeed, use time {}ms", u.getClass().getName(), st1.elapsed(TimeUnit.MILLISECONDS));
    }

    public static <T, ID> void saveWithTimeLog(CrudRepository<T, ID> cr, T t) {
        saveWithTimeLog((CrudRepository<T, ID> r, T t1) -> r.save(t1), cr, t);
    }

    public static <T, ID> void saveAllWithTimeLog(CrudRepository<T, ID> cr, Collection<T> t) {
        saveWithTimeLog((CrudRepository<T, ID> r, Collection<T> t1) -> r.saveAll(t1), cr, t);
    }

}
